package oidcprovider

import (
	"context"
	"fmt"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/rancher/rancher/pkg/auth/providers/keycloakoidc"
	"github.com/rancher/rancher/pkg/auth/providers/oidc"
	"net/http"
	"net/url"
	"time"
)

type keycloak struct {
	provider *keycloakoidc.KeyCloakOIDCProvider
}

func newKeycloak(provider *keycloakoidc.KeyCloakOIDCProvider) *keycloak {
	return &keycloak{
		provider: provider,
	}
}

func (k *keycloak) ShowLoginPage(w http.ResponseWriter, r *http.Request) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "failed to parse values", http.StatusInternalServerError)
	}
	state := values.Get("state")
	nonce := values.Get("nonce")

	c, err := k.provider.GetOIDCConfig()
	if err != nil {
		http.Error(w, "failed to get config", http.StatusInternalServerError)
		return
	}
	url := c.AuthEndpoint + "?client_id=" + c.ClientID + "&response_type=code&redirect_uri=" + c.RancherURL + "&scope=openid%20profile%20email&state=oidc-provider:::" + state + ":::" + nonce // TODO using ::: as divider is not safe look for a better approach!
	http.Redirect(w, r, url, http.StatusFound)
}

func (k *keycloak) Login(r *http.Request) (*openid.DefaultSession, error) {
	ctx := context.Background()
	var userClaimInfo oidc.ClaimInfo
	code := r.URL.Query().Get("code")
	nonce := r.URL.Query().Get("nonce")

	config, err := k.provider.GetOIDCConfig()
	if err != nil {
		return nil, err
	}

	userInfo, oauth2Token, err := k.provider.GetUserInfo(&ctx, config, code, &userClaimInfo, "")
	if err != nil {
		return nil, err
	}
	userPrincipal := k.provider.UserToPrincipal(userInfo, userClaimInfo)
	groupPrincipals := k.provider.GetGroupsFromClaimInfo(userClaimInfo)
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
	}

	return mySession, nil
}
