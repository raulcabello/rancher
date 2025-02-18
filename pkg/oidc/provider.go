package oidc

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/rancher/rancher/pkg/ext/oidcclients"
	wrangmgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/oidc/auth"
	"github.com/rancher/rancher/pkg/oidc/jwks"
	"github.com/rancher/rancher/pkg/oidc/session"
	"github.com/rancher/rancher/pkg/oidc/token"
	"github.com/rancher/rancher/pkg/settings"
	corecontrollers "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	"net/http"
	"time"
)

type Provider struct {
	jwksHandler  *jwks.Handler
	authHandler  *auth.Handler
	tokenHandler *token.Handler
}

func NewProvider(ctx context.Context, tokenCache wrangmgmtv3.TokenCache, userLister wrangmgmtv3.UserCache, userAttributeLister wrangmgmtv3.UserAttributeCache, secretCache corecontrollers.SecretCache, secretClient corecontrollers.SecretClient) Provider {
	sessionStorage := session.NewMemoryStorage(ctx, 10*time.Minute) //TODO check idle timeout
	jwks, err := jwks.NewHandler(secretCache, secretClient)
	if err != nil {
		//TODO!!
	}
	oidcClientCache := oidcclients.NewStoreCache(secretCache)

	return Provider{
		jwksHandler:  jwks,
		authHandler:  auth.NewHandler(tokenCache, userLister, sessionStorage, &session.WranglerCodeCreator{}, oidcClientCache),
		tokenHandler: token.NewHandler(tokenCache, userLister, userAttributeLister, sessionStorage, jwks),
	}
}

func (p *Provider) RegisterOIDCProviderHandles(mux *mux.Router) {
	mux.HandleFunc("/oidc/token", p.tokenHandler.TokenEndpoint)

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
			"id_token_signing_alg_values_supported": ["RS256"],
			"code_challenge_methods_supported": ["S256"]
		}`)) //TODO add PKCE!
	})

	mux.HandleFunc("/oidc/.well-known/jwks.json", p.jwksHandler.JWKSEndpoint)

	mux.HandleFunc("/oidc/authorize", p.authHandler.AuthEndpoint)

}

func OIDCProviderHost() string {
	return settings.ServerURL.Get() + "/oidc"
}
