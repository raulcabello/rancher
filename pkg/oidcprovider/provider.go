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
	"github.com/rancher/rancher/pkg/settings"
	"golang.org/x/crypto/bcrypt"
	"log"
	"math/big"
	"net/http"
	"time"
)

type authProvider interface {
	ShowLoginPage(w http.ResponseWriter, r *http.Request)
	Login(r *http.Request) (*openid.DefaultSession, error)
}

const ClientID = "oidc-client"

var (
	Host       string
	privateKey *rsa.PrivateKey
)

// Initialize Fosite provider
func newOAuth2Provider() fosite.OAuth2Provider {
	Host = settings.ServerURL.Get() + "/oidc"
	// This secret is being used to sign access and refresh tokens as well as
	// authorization codes. It must be exactly 32 bytes long.
	var secret = []byte("BimPY6GrQCX2cYPJi3b1jxxAlci2/cS")
	bytes, err := bcrypt.GenerateFromPassword([]byte(secret), 14)

	// In-memory storage for simplicity
	store := storage.NewMemoryStore()
	store.Clients[ClientID] = &fosite.DefaultClient{
		ID:     ClientID,
		Secret: bytes,
		RedirectURIs: []string{
			"http://localhost:8000", // TODO harcoded for https://github.com/int128/kubelogin. Should be customizable!
		},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email"},
	}

	// Generate an RSA key for signing JWTs (ID tokens)
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate RSA key: %v", err)
	}

	// Setup the Fosite provider
	config := &fosite.Config{
		AccessTokenLifespan: time.Minute * 30,
		GlobalSecret:        bytes,
	}

	oauth2Provider := compose.ComposeAllEnabled(config, store, privateKey)

	return oauth2Provider
}

func RegisterOIDCProviderHandles(mux *mux.Router) {
	oauth2Provider := newOAuth2Provider()

	mux.HandleFunc("/oidc/authorize/callback", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.TODO()

		p, err := getActiveProvider()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session, err := p.Login(r)
		if err != nil {
			http.Error(w, "failed to login: "+err.Error(), http.StatusInternalServerError)
			return
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
			"issuer": "` + Host + `",
			"authorization_endpoint": "` + Host + `/authorize",
			"token_endpoint": "` + Host + `/token",
			"jwks_uri": "` + Host + `/.well-known/jwks.json",
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
					Kid: "unique-key-id", // Replace with a unique identifier for your key
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
		p, err := getActiveProvider()
		if err != nil {
			http.Error(w, "failed to get config", http.StatusInternalServerError)
			return
		}
		p.ShowLoginPage(w, r)
	})

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
