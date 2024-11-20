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
	"html/template"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"time"
)

const ClientID = "oidc-client"

var (
	Host         string
	privateKey   *rsa.PrivateKey
	state, nonce string //TODO change this!!
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
	// /authorize endpoint
	mux.HandleFunc("/oidc/authorize/callback", func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()
		var userClaimInfo oidc.ClaimInfo
		code := r.URL.Query()["code"][0]
		p, err := providers.GetProvider(keycloakoidc.Name)
		if err != nil {
			panic("TODO remove") //TODO
			return
		}

		o := p.(*keycloakoidc.KeyCloakOIDCProvider)
		if err != nil {
			panic("TODO remove") //TODO
			return
		}

		config, err := o.GetOIDCConfig()
		if err != nil {
			panic("TODO remove") //TODO
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
				Nonce:       nonce, //TODO pass nonce through rancher redirect
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

	tmpl := template.Must(template.New("page").Parse(`
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Rancher OIDC</title>
	</head>
	<body>
		<h1>Welcome Rancher OIDC Login!</h1>
		<button onclick="window.location.href='/oidc/redirect'">Login</button>
	</body>
	</html>
	`))

	// Handler for the main page
	mux.HandleFunc("/oidc/login", func(w http.ResponseWriter, r *http.Request) {
		tmpl.Execute(w, nil)
	})

	mux.HandleFunc("/oidc/authorize", func(w http.ResponseWriter, r *http.Request) {
		values, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			fmt.Println(err) //TODO
		}
		state = values.Get("state")
		nonce = values.Get("nonce")

		http.Redirect(w, r, Host+"/login", http.StatusFound)
	})

	// Handler for the redirect
	mux.HandleFunc("/oidc/redirect", func(w http.ResponseWriter, r *http.Request) {
		p, err := providers.GetProvider(keycloakoidc.Name)
		if err != nil {
			panic("TODO remove") //TODO
			return
		}

		o := p.(*keycloakoidc.KeyCloakOIDCProvider)
		if err != nil {
			panic("TODO remove") //TODO
			return
		}
		c, err := o.GetOIDCConfig()
		if err != nil {
			panic("TODO remove") //TODO
			return
		}
		url := c.AuthEndpoint + "?client_id=" + c.ClientID + "&response_type=code&redirect_uri=" + c.RancherURL + "&scope=openid%20profile%20email&state=oidc-provider:" + state + "&nonce=" + nonce
		http.Redirect(w, r, url, http.StatusFound)
	})

	mux.HandleFunc("/oidc/login", func(w http.ResponseWriter, r *http.Request) {
		tmpl.Execute(w, nil)
	})

	// Start HTTP server
	//	log.Println("Server is running at " + Host)
	//	log.Fatal(http.ListenAndServe(":8082", nil))
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
