package oidcprovider

import (
	"encoding/json"
	"fmt"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers"
	"github.com/rancher/rancher/pkg/auth/providers/keycloakoidc"
	"github.com/rancher/rancher/pkg/auth/providers/ldap"
	"github.com/rancher/rancher/pkg/settings"
	"io/ioutil"
	"net/http"
)

type Response struct {
	Data []v3.AuthProvider `json:"data"`
}

func getActiveProvider() (authProvider, error) {
	// TODO find a better way of finding current provider. Avoid making an http request each time!
	resp, err := http.Get(settings.ServerURL.Get() + "/v3-public/authProviders")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResponse Response
	err = json.Unmarshal(body, &apiResponse)
	if err != nil {
		return nil, err

	}

	providerName := ""
	for _, p := range apiResponse.Data {
		if p.Type != "localProvider" { // ignore local provider
			providerName = p.Type
		}
	}

	provider := providers.GetProviderByType(providerName)

	switch p := provider.(type) {
	case *keycloakoidc.KeyCloakOIDCProvider:
		return newKeycloak(p), nil
	case *ldap.LdapProvider:
		return newLdapProvider(p), nil
	}

	return nil, fmt.Errorf("unsupported provider")
}
