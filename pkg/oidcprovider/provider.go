package oidcprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"github.com/rancher/rancher/pkg/auth/providers"
	"github.com/rancher/rancher/pkg/auth/providers/keycloakoidc"
	"github.com/rancher/rancher/pkg/auth/providers/oidc"
	"golang.org/x/crypto/bcrypt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"time"
)

const ClientID = "oidc-client"

var (
	Host       string
	privateKey *rsa.PrivateKey
)

// Initialize Fosite provider
func newOAuth2Provider() fosite.OAuth2Provider {
	Host = "https://4d0594e765e9.ngrok.app/oidc" //settings.ServerURL.Get() + "/oidc"
	// This secret is being used to sign access and refresh tokens as well as
	// authorization codes. It must be exactly 32 bytes long.
	var secret = []byte("BimPY6GrQCX2cYPJi3b1jxxAlci2/cS")
	bytes, err := bcrypt.GenerateFromPassword([]byte(secret), 14)

	// In-memory storage for simplicity
	store := storage.NewMemoryStore()
	// Example client (you can fetch these from a database instead)
	store.Clients[ClientID] = &fosite.DefaultClient{
		ID:     ClientID,
		Secret: bytes,
		RedirectURIs: []string{
			Host + "/callback",
			"http://localhost:8000",
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
		ctx := context.Background()
		var userClaimInfo oidc.ClaimInfo
		// TODO avoid panic if code or nonce not provided!
		code := r.URL.Query()["code"][0]
		nonce := r.URL.Query()["nonce"][0]

		// TODO it could be any provider!
		p, err := providers.GetProvider(keycloakoidc.Name)
		if err != nil {
			http.Error(w, "failed to parse provider", http.StatusInternalServerError)
			return
		}

		o := p.(*keycloakoidc.KeyCloakOIDCProvider)
		if err != nil {
			http.Error(w, "failed to parse provider", http.StatusInternalServerError)
			return
		}

		config, err := o.GetOIDCConfig()
		if err != nil {
			http.Error(w, "failed to get config", http.StatusInternalServerError)
			return
		}

		userInfo, oauth2Token, err := o.GetUserInfo(&ctx, config, code, &userClaimInfo, "")
		userPrincipal := o.UserToPrincipal(userInfo, userClaimInfo)
		groupPrincipals := o.GetGroupsFromClaimInfo(userClaimInfo)
		fmt.Println(userInfo)
		fmt.Println(oauth2Token)
		fmt.Println(userPrincipal)
		fmt.Println(groupPrincipals)

		var mySession = &openid.DefaultSession{
			Username: userClaimInfo.PreferredUsername,
			Subject:  userClaimInfo.PreferredUsername,
			Claims: &jwt.IDTokenClaims{
				Issuer:      Host,
				Nonce:       nonce,
				Subject:     userClaimInfo.PreferredUsername,
				Audience:    []string{"https://my-client.my-application.com"}, //TODO change!
				ExpiresAt:   time.Now().Add(time.Hour * 6),
				IssuedAt:    time.Now(),
				RequestedAt: time.Now(),
				AuthTime:    time.Now(),
				Extra: map[string]interface{}{
					"groups": userClaimInfo.Groups,
				},
			},
			Headers: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
		} // Customize this session for your needs

		// Handle authorization request
		authorizeRequest, err := oauth2Provider.NewAuthorizeRequest(ctx, r)
		if err != nil {
			oauth2Provider.WriteAuthorizeError(ctx, w, authorizeRequest, err)
			return
		}
		authorizeRequest.GrantScope("openid")
		authorizeRequest.GrantScope("email")
		authorizeRequest.GrantScope("profile")

		// Validate client and issue an authorization code
		response, err := oauth2Provider.NewAuthorizeResponse(ctx, authorizeRequest, mySession)
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
		values, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, "failed to parse values", http.StatusInternalServerError)
		}
		state := values.Get("state")
		nonce := values.Get("nonce")

		// TODO it could be any provider!
		p, err := providers.GetProvider(keycloakoidc.Name)
		if err != nil {
			http.Error(w, "failed to find provider", http.StatusInternalServerError)
			return
		}

		o := p.(*keycloakoidc.KeyCloakOIDCProvider)
		if err != nil {
			http.Error(w, "failed to parse provider", http.StatusInternalServerError)
			return
		}
		c, err := o.GetOIDCConfig()
		if err != nil {
			http.Error(w, "failed to get config", http.StatusInternalServerError)
			return
		}
		url := c.AuthEndpoint + "?client_id=" + c.ClientID + "&response_type=code&redirect_uri=" + c.RancherURL + "&scope=openid%20profile%20email&state=oidc-provider:::" + state + ":::" + nonce // TODO using ::: as divider is not safe look for a better approach!
		http.Redirect(w, r, url, http.StatusFound)                                                                                                                                                 //redirect to keycloack. Then keycloack will redirect to Rancher verify-auth
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
