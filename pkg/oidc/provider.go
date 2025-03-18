package oidc

import (
	"context"
	"github.com/gorilla/mux"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	wrangmgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/oidc/auth"
	"github.com/rancher/rancher/pkg/oidc/jwks"
	"github.com/rancher/rancher/pkg/oidc/session"
	"github.com/rancher/rancher/pkg/oidc/token"
	"github.com/rancher/rancher/pkg/settings"
	corecontrollers "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"net/http"
	"time"
)

const (
	oidcClientByIDIndex = "oidc.management.cattle.io/oidcclient-by-id"
	secretsNamespace    = "cattle-oidc-client-secrets"
	codesNamespace      = "cattle-oidc-codes"
)

type Provider struct {
	jwksHandler  *jwks.Handler
	authHandler  *auth.Handler
	tokenHandler *token.Handler
}

func NewProvider(ctx context.Context, tokenCache wrangmgmtv3.TokenCache, tokenClient wrangmgmtv3.TokenClient, userLister wrangmgmtv3.UserCache, userAttributeLister wrangmgmtv3.UserAttributeCache, secretCache corecontrollers.SecretCache, secretClient corecontrollers.SecretClient, oidcClientCache wrangmgmtv3.OIDCClientCache, oidcClientController wrangmgmtv3.OIDCClientController, namespaceClient corecontrollers.NamespaceClient) (Provider, error) {
	sessionStorage := session.NewSecretStorage(ctx, secretCache, secretClient, 10*time.Minute) //TODO check idle timeout
	jwks, err := jwks.NewHandler(secretCache, secretClient)
	if err != nil {
		return Provider{}, err
	}
	oidcClientInformer := oidcClientController.Informer()
	userIndexers := map[string]cache.IndexFunc{
		oidcClientByIDIndex: func(obj interface{}) ([]string, error) {
			o, ok := obj.(*v3.OIDCClient)
			if !ok {
				return []string{}, nil
			}

			return []string{o.Status.ClientID}, nil
		},
	}
	err = oidcClientInformer.AddIndexers(userIndexers)
	if err != nil {
		return Provider{}, err
	}
	// create necessary namespaces
	if _, err := namespaceClient.Create(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretsNamespace,
		},
	}); err != nil && !apierrors.IsAlreadyExists(err) {
		return Provider{}, err
	}
	if _, err := namespaceClient.Create(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: codesNamespace,
		},
	}); err != nil && !apierrors.IsAlreadyExists(err) {
		return Provider{}, err
	}

	return Provider{
		jwksHandler:  jwks,
		authHandler:  auth.NewHandler(tokenCache, userLister, sessionStorage, &session.RandomStringGenerator{}, oidcClientCache),
		tokenHandler: token.NewHandler(tokenCache, userLister, userAttributeLister, sessionStorage, jwks, oidcClientCache, secretCache, tokenClient),
	}, nil
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
