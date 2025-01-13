package oidcprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"github.com/rancher/rancher/pkg/auth/providers"
	"github.com/rancher/rancher/pkg/auth/tokens"
	wrangmgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/settings"
	"golang.org/x/crypto/bcrypt"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const ClientID = "oidc-client"

var (
	privateKey     *rsa.PrivateKey
	oauth2Provider fosite.OAuth2Provider
)

func init() {
	var err error
	// Generate an RSA key for signing JWTs (ID tokens)
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048) //TODO key rotation
	if err != nil {
		log.Fatalf("failed to generate RSA key: %v", err)
	}

}

// Initialize Fosite provider
func NewOAuth2Provider() {
	// This secret is being used to sign access and refresh tokens as well as
	// authorization codes. It must be exactly 32 bytes long.
	var secret = []byte("BimPY6GrQCX2cYPJi3b1jxxAlci2/cS") //TODO rotation?
	bytes, err := bcrypt.GenerateFromPassword([]byte(secret), 14)
	if err != nil {
		log.Fatalf("failed to generate secret: %v", err)
	}

	// In-memory storage for simplicity
	store := storage.NewMemoryStore()
	store.Clients[ClientID] = &fosite.DefaultClient{
		ID:     ClientID,
		Secret: bytes,
		RedirectURIs: []string{
			"http://localhost:8088/callback",
			"http://localhost:8000",
			settings.OIDCRedirectURI.Get(),
		},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email", "offline_access"},
	}

	// Setup the Fosite provider
	config := &fosite.Config{
		AccessTokenLifespan:  time.Minute * 30,
		RefreshTokenLifespan: time.Hour * 48,
		GlobalSecret:         bytes,
	}

	oauth2Provider = compose.ComposeAllEnabled(config, store, privateKey)
}

func RegisterOIDCProviderHandles(mux *mux.Router, tokenCache wrangmgmtv3.TokenCache, userLister wrangmgmtv3.UserCache, userAttributeLister wrangmgmtv3.UserAttributeCache) {
	NewOAuth2Provider()

	mux.HandleFunc("/oidc/authorize/callback", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.TODO()

		tokenAuthValue := tokens.GetTokenAuthFromRequest(r)
		if tokenAuthValue == "" {
			http.Error(w, "failed to authenticate ", http.StatusInternalServerError)
			return
		}

		tokenName, tokenKey := tokens.SplitTokenParts(tokenAuthValue)
		if tokenName == "" || tokenKey == "" {
			http.Error(w, "failed to authenticate ", http.StatusInternalServerError)
			return
		}

		token, err := tokenCache.Get(tokenName)
		if err != nil {
			oauth2Provider.WriteAuthorizeError(ctx, w, nil, err)
			return
		}
		if token.Token != tokenKey {
			oauth2Provider.WriteAuthorizeError(ctx, w, nil, err)
			return
		}
		if token.Enabled != nil && !*token.Enabled {
			http.Error(w, "failed to authenticate ", http.StatusInternalServerError)
			return
		}

		// If the auth provider is specified make sure it exists and enabled.
		if token.AuthProvider != "" {
			disabled, err := providers.IsDisabledProvider(token.AuthProvider)
			if err != nil {
				http.Error(w, "failed to authenticate ", http.StatusInternalServerError)
				return
			}
			if disabled {
				http.Error(w, "failed to authenticate ", http.StatusInternalServerError)
				return
			}
		}

		attribs, err := userAttributeLister.Get(token.UserID)
		if err != nil && !apierrors.IsNotFound(err) {
			http.Error(w, "failed to authenticate ", http.StatusInternalServerError)
			return
		}

		authUser, err := userLister.Get(token.UserID)
		if err != nil {
			http.Error(w, "failed to authenticate ", http.StatusInternalServerError)
			return
		}

		if authUser.Enabled != nil && !*authUser.Enabled {
			http.Error(w, "failed to authenticate ", http.StatusInternalServerError)
			return
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

		var session = &openid.DefaultSession{
			Username: token.UserID,
			Subject:  token.UserID,
			Claims: &jwt.IDTokenClaims{
				Issuer:      OIDCProviderHost(),
				Nonce:       "nonce",
				Subject:     token.UserID,
				ExpiresAt:   time.Now().Add(time.Hour * 6),
				IssuedAt:    time.Now(),
				RequestedAt: time.Now(),
				AuthTime:    time.Now(),
				Extra: map[string]interface{}{
					"groups":             groups,
					"preferred_username": authUser.DisplayName,
				},
			},
			Headers: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
		}
		// Handle authorization request
		authorizeRequest, err := oauth2Provider.NewAuthorizeRequest(ctx, r)
		if err != nil {
			oauth2Provider.WriteAuthorizeError(ctx, w, authorizeRequest, err)
			return
		}
		// TODO configure scopes
		authorizeRequest.GrantScope("openid")
		authorizeRequest.GrantScope("email")
		authorizeRequest.GrantScope("profile")
		authorizeRequest.GrantScope("offline_access")

		// Validate client and issue an authorization code
		response, err := oauth2Provider.NewAuthorizeResponse(ctx, authorizeRequest, session)
		if err != nil {
			oauth2Provider.WriteAuthorizeError(ctx, w, authorizeRequest, err)
			return
		}

		oauth2Provider.WriteAuthorizeResponse(ctx, w, authorizeRequest, response)
	})

	// /token endpoint
	mux.HandleFunc("/oidc/token", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		var mySession = &openid.DefaultSession{}

		// Handle token request
		accessRequest, err := oauth2Provider.NewAccessRequest(ctx, r, mySession)
		if err != nil {
			oauth2Provider.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		response, err := oauth2Provider.NewAccessResponse(ctx, accessRequest)
		if err != nil {
			oauth2Provider.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		oauth2Provider.WriteAccessResponse(ctx, w, accessRequest, response)
	})

	// /.well-known/openid-configuration endpoint
	mux.HandleFunc("/oidc/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"issuer": "` + OIDCProviderHost() + `",
			"authorization_endpoint": "` + OIDCProviderHost() + `/authorize",
			"token_endpoint": "` + OIDCProviderHost() + `/token",
			"jwks_uri": "` + OIDCProviderHost() + `/.well-known/jwks.json",
			"response_types_supported": ["code"],
			"subject_types_supported": ["public"],
			"id_token_signing_alg_values_supported": ["RS256"]
		}`))
	})

	mux.HandleFunc("/oidc/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		pubKey := privateKey.PublicKey
		n := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes())
		jwks := JWKS{
			Keys: []JWK{
				{
					Kty: "RSA",
					Use: "sig",
					Kid: "unique-key-id", // TODO Replace with a unique identifier for key
					N:   n,
					E:   e,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			http.Error(w, "failed to encode JWKS", http.StatusInternalServerError)
		}
	})

	// entry point for auth flow
	mux.HandleFunc("/oidc/authorize", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, settings.ServerURL.Get()+"/dashboard/auth/login?client_id=oidc-client&redirect_uri="+r.URL.Query().Get("redirect_uri")+"&response_type=code&scope=openid+email+profile&state="+r.URL.Query().Get("state")+"&nonce="+r.URL.Query().Get("nonce"), http.StatusFound)
	})

}

func OIDCProviderHost() string {
	return settings.ServerURL.Get() + "/oidc"
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key Type (e.g., RSA)
	Use string `json:"use"` // Key Usage (e.g., sig)
	Kid string `json:"kid"` // Key ID
	N   string `json:"n"`   // Modulus
	E   string `json:"e"`   // Exponent
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}
