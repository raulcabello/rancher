package token

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/tokens"
	wrangmgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/oidc/session"
	"github.com/rancher/rancher/pkg/settings"
	"golang.org/x/oauth2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"net/http"
	"slices"
	"strings"
	"time"
)

type signingKeyGetter interface {
	GetSigningKey() (*rsa.PrivateKey, string, error)
	GetPublicKey(kid string) (*rsa.PublicKey, error)
}

type Handler struct {
	tokenCache          wrangmgmtv3.TokenCache
	userLister          wrangmgmtv3.UserCache
	userAttributeLister wrangmgmtv3.UserAttributeCache
	sessionStorage      session.Storage
	jwks                signingKeyGetter
}

type TokenResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	// TODO add expiry?
}

type RefreshTokenClaims struct {
	jwt.RegisteredClaims
	UserID           string   `json:"user_id"`
	RancherTokenHash string   `json:"rancher_token_hash"`
	Scope            []string `json:"scope"`
}

func NewHandler(tokenCache wrangmgmtv3.TokenCache, userLister wrangmgmtv3.UserCache, userAttributeLister wrangmgmtv3.UserAttributeCache, sessionStorage session.Storage, jwks signingKeyGetter) *Handler {
	return &Handler{
		tokenCache:          tokenCache,
		userLister:          userLister,
		userAttributeLister: userAttributeLister,
		sessionStorage:      sessionStorage,
		jwks:                jwks,
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
	// TODO check client secret!
	clientID, _, ok := r.BasicAuth()
	if !ok || clientID != session.ClientID {
		return TokenResponse{}, fmt.Errorf("invalid client_id")
	}

	//verify sessionStorage PKCE
	code_verifier := r.Form.Get("code_verifier")
	if session.CodeChallenge != oauth2.S256ChallengeFromVerifier(code_verifier) {
		return TokenResponse{}, fmt.Errorf("failed to verify PKCE sessionStorage challenge")
	}

	rancherToken, err := h.tokenCache.Get(session.TokenName)
	if err != nil {
		return TokenResponse{}, err
	}

	return h.createTokenResponse(rancherToken, session.ClientID, session.Nonce, session.Scope)

}

func (h *Handler) createTokenResponse(rancherToken *v3.Token, clientID string, nonce string, scopes []string) (TokenResponse, error) {
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

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256,
		jwt.MapClaims{
			"aud":                []string{clientID},
			"exp":                time.Now().Add(time.Hour * 24).Unix(), //TODO exp
			"iss":                settings.ServerURL.Get() + "/oidc",    //TODO
			"iat":                time.Now().Unix(),
			"nonce":              nonce,
			"preferred_username": user.DisplayName,
			"sub":                rancherToken.UserID,
			"groups":             groups, // TODO exclude if no groups present
		})
	idToken.Header["kid"] = kid
	idTokenString, err := idToken.SignedString(key)
	if err != nil {
		return TokenResponse{}, err
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256,
		jwt.MapClaims{
			"aud":   []string{clientID},
			"exp":   time.Now().Add(time.Hour * 24).Unix(), //TODO exp
			"iss":   settings.ServerURL.Get() + "/oidc",    //TODO
			"iat":   time.Now().Unix(),
			"sub":   rancherToken.UserID,
			"scope": scopes, //TODO array fine here? or string needed?
		})
	accessToken.Header["kid"] = kid

	accessTokenString, err := accessToken.SignedString(key)
	if err != nil {
		return TokenResponse{}, err
	}
	resp := TokenResponse{
		IDToken:     idTokenString,
		AccessToken: accessTokenString,
	}
	hash := sha256.Sum256([]byte(rancherToken.Name))
	rancherTokenHash := hex.EncodeToString(hash[:])

	if slices.Contains(scopes, "offline_access") {
		// TODO add refresh token id to rancher token for invalidation!
		refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256,
			jwt.MapClaims{
				"aud":                []string{clientID},
				"exp":                time.Now().Add(time.Hour * 24).Unix(), //TODO exp
				"iat":                time.Now().Unix(),
				"user_id":            rancherToken.UserID,
				"rancher_token_hash": rancherTokenHash, //TODO add sub??
				"scope":              scopes,
			})
		refreshToken.Header["kid"] = kid
		refreshTokenString, err := refreshToken.SignedString(key)
		if err != nil {
			return TokenResponse{}, err
		}
		resp.RefreshToken = refreshTokenString
	}

	return resp, nil
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
		tokens.UserIDLabel: claims.UserID,
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

	//TODO check audience
	return h.createTokenResponse(rancherToken, claims.Audience[0], "", claims.Scope)
}
