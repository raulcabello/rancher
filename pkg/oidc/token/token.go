package token

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	v1 "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers"
	"github.com/rancher/rancher/pkg/auth/tokens"
	"github.com/rancher/rancher/pkg/ext/oidcclients"
	wrangmgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/oidc/session"
	"github.com/rancher/rancher/pkg/settings"
	"golang.org/x/oauth2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type SigningKeyGetter interface {
	GetSigningKey() (*rsa.PrivateKey, string, error)
	GetPublicKey(kid string) (*rsa.PublicKey, error)
}

type Handler struct {
	tokenCache          wrangmgmtv3.TokenCache
	tokenClient         wrangmgmtv3.TokenClient
	userLister          wrangmgmtv3.UserCache
	userAttributeLister wrangmgmtv3.UserAttributeCache
	sessionStorage      session.Storage
	oidcClientCache     *oidcclients.StoreCache
	jwks                SigningKeyGetter
	now                 func() time.Time
}

type TokenResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
}

type RefreshTokenClaims struct {
	jwt.RegisteredClaims
	RancherTokenHash string   `json:"rancher_token_hash"`
	Scope            []string `json:"scope"`
}

func NewHandler(tokenCache wrangmgmtv3.TokenCache, userLister wrangmgmtv3.UserCache, userAttributeLister wrangmgmtv3.UserAttributeCache, sessionStorage session.Storage, jwks SigningKeyGetter, oidcClientCache *oidcclients.StoreCache, tokenClient wrangmgmtv3.TokenClient) *Handler {
	return &Handler{
		tokenCache:          tokenCache,
		tokenClient:         tokenClient,
		userLister:          userLister,
		userAttributeLister: userAttributeLister,
		sessionStorage:      sessionStorage,
		jwks:                jwks,
		oidcClientCache:     oidcClientCache,
		now:                 time.Now,
	}
}

func (h *Handler) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch r.Form.Get("grant_type") {
	case "authorization_code":
		tokenResponse, err := h.createTokenFromCode(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(tokenResponse)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "refresh_token":
		tokens, err := h.refreshToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(tokens)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "grant_type not supported", http.StatusInternalServerError)
		return
	}
}

func (h *Handler) createTokenFromCode(r *http.Request) (TokenResponse, error) {
	session, err := h.sessionStorage.GetAndRemoveSession(r.FormValue("code"))
	if err != nil {
		return TokenResponse{}, err
	}
	var clientID, clientSecret string
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	if clientID != session.ClientID {
		return TokenResponse{}, fmt.Errorf("invalid client_id")
	}
	oidcClient, err := h.oidcClientCache.GetFromCache(clientID)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("error retreiving OIDC client: %v", err)
	}
	clientSecretUnescaped, err := url.QueryUnescape(clientSecret)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("can't unescape client secret: %v", err)
	}
	if oidcClient.Spec.Secret != clientSecretUnescaped {
		return TokenResponse{}, fmt.Errorf("invalid client secret")
	}

	code_verifier := r.Form.Get("code_verifier")
	if session.CodeChallenge != oauth2.S256ChallengeFromVerifier(code_verifier) {
		return TokenResponse{}, fmt.Errorf("failed to verify PKCE code challenge")
	}

	rancherToken, err := h.tokenCache.Get(session.TokenName)
	if err != nil {
		return TokenResponse{}, err
	}

	return h.createResponse(rancherToken, oidcClient, session.Nonce, session.Scope)
}

func (h *Handler) refreshToken(r *http.Request) (TokenResponse, error) {
	refreshToken := r.Form.Get("refresh_token")
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure correct signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("can't find kid")
		}
		pubKey, err := h.jwks.GetPublicKey(kid)
		if err != nil {
			return nil, err //TODO msg
		}

		return pubKey, nil
	})
	if err != nil {
		return TokenResponse{}, err
	}
	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok && !token.Valid {
		return TokenResponse{}, fmt.Errorf("TODO")
	}

	tokenList, err := h.tokenCache.List(labels.SelectorFromSet(map[string]string{
		tokens.UserIDLabel: claims.Subject,
	}))
	if err != nil {
		return TokenResponse{}, err
	}
	var rancherToken *v3.Token
	for _, token := range tokenList {
		hash := sha256.Sum256([]byte(token.Name))
		rancherTokenHash := hex.EncodeToString(hash[:])
		if rancherTokenHash == claims.RancherTokenHash {
			rancherToken = token
			break
		}
	}

	if rancherToken == nil {
		return TokenResponse{}, fmt.Errorf("can't find rancher token")
	}

	if len(claims.Audience) < 1 {
		return TokenResponse{}, fmt.Errorf("can't find client in audience")
	}
	oidcClient, err := h.oidcClientCache.GetFromCache(claims.Audience[0])
	if err != nil {
		return TokenResponse{}, fmt.Errorf("error retreiving OIDC client from audience: %v", err)
	}

	return h.createResponse(rancherToken, oidcClient, "", claims.Scope)
}

func (h *Handler) createResponse(rancherToken *v3.Token, oidcClient *v1.OIDCClient, nonce string, scopes []string) (TokenResponse, error) {
	if rancherToken.Expired {
		return TokenResponse{}, fmt.Errorf("rancher token is expired")
	}
	if rancherToken.Enabled == nil || !*rancherToken.Enabled {
		return TokenResponse{}, fmt.Errorf("rancher token is disabled")
	}
	if rancherToken.AuthProvider != "" {
		disabled, err := providers.IsDisabledProvider(rancherToken.AuthProvider)
		if err != nil {
			return TokenResponse{}, fmt.Errorf("can't check if auth provider is disabled: %v", err)
		}
		if disabled {
			return TokenResponse{}, fmt.Errorf("auth provider is disabled")
		}
	}
	user, err := h.userLister.Get(rancherToken.UserID)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("can't get user: %v", err)
	}
	if user.Enabled != nil && !*user.Enabled {
		return TokenResponse{}, fmt.Errorf("user is disabled")
	}
	attribs, err := h.userAttributeLister.Get(rancherToken.UserID)
	if err != nil && !apierrors.IsNotFound(err) {
		return TokenResponse{}, fmt.Errorf("can't get user attributes: %v", err)
	}
	var groups []string
	if attribs != nil {
		for _, gps := range attribs.GroupPrincipals {
			for _, principal := range gps.Items {
				name := strings.TrimPrefix(principal.Name, "local://")
				groups = append(groups, name)
			}
		}
	}
	key, kid, err := h.jwks.GetSigningKey()
	if err != nil {
		return TokenResponse{}, err
	}

	idClaims := jwt.MapClaims{
		"aud": []string{oidcClient.Name},
		"exp": h.now().Add(oidcClient.Spec.TokenLifeSpan).Unix(),
		"iss": settings.ServerURL.Get() + "/oidc",
		"iat": h.now().Unix(),
		"sub": rancherToken.UserID,
	}
	if slices.Contains(scopes, "profile") {
		idClaims["preferred_username"] = user.DisplayName
	}
	if nonce != "" {
		idClaims["nonce"] = nonce
	}
	if groups != nil {
		idClaims["groups"] = groups
	}
	if rancherToken.AuthProvider != "" {
		idClaims["auth_provider"] = rancherToken.AuthProvider
	}
	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
	idToken.Header["kid"] = kid
	idTokenString, err := idToken.SignedString(key)
	if err != nil {
		return TokenResponse{}, err
	}

	accessClaims := jwt.MapClaims{
		"aud":   []string{oidcClient.Name},
		"exp":   h.now().Add(oidcClient.Spec.TokenLifeSpan).Unix(),
		"iss":   settings.ServerURL.Get() + "/oidc", //TODO
		"iat":   h.now().Unix(),
		"sub":   rancherToken.UserID,
		"scope": scopes,
	}
	if rancherToken.AuthProvider != "" {
		accessClaims["auth_provider"] = rancherToken.AuthProvider
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = kid

	accessTokenString, err := accessToken.SignedString(key)
	if err != nil {
		return TokenResponse{}, err
	}
	resp := TokenResponse{
		IDToken:     idTokenString,
		AccessToken: accessTokenString,
	}

	if slices.Contains(scopes, "offline_access") {
		hash := sha256.Sum256([]byte(rancherToken.Name))
		rancherTokenHash := hex.EncodeToString(hash[:])
		refreshTokenID := oidcClient.Name + "-" + rancherToken.UserID
		refreshClaims := jwt.MapClaims{
			"aud":                []string{oidcClient.Name},
			"exp":                h.now().Add(oidcClient.Spec.RefreshTokenLifeSpan).Unix(),
			"iat":                h.now().Unix(),
			"sub":                rancherToken.UserID,
			"rancher_token_hash": rancherTokenHash,
			"scope":              scopes,
			"id":                 refreshTokenID,
		}
		if rancherToken.AuthProvider != "" {
			refreshClaims["auth_provider"] = rancherToken.AuthProvider
		}
		refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
		refreshToken.Header["kid"] = kid
		refreshTokenString, err := refreshToken.SignedString(key)
		if err != nil {
			return TokenResponse{}, err
		}
		resp.RefreshToken = refreshTokenString

		if err := h.addOIDCClientIDToRancherToken(oidcClient.Name, rancherToken.Name); err != nil {
			return TokenResponse{}, err
		}
	}

	resp.ExpiresIn = int(oidcClient.Spec.TokenLifeSpan.Seconds())

	return resp, nil
}

func (h *Handler) addOIDCClientIDToRancherToken(oidcClientName string, rancherTokenName string) error {
	patch, err := json.Marshal([]struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value"`
	}{{
		Op:    "add",
		Path:  "/metadata/labels/" + oidcClientName,
		Value: "true",
	}})
	if err != nil {
		return err
	}
	_, err = h.tokenClient.Patch(rancherTokenName, types.JSONPatchType, patch)

	return err
}
