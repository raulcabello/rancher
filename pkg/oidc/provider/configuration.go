package provider

import (
	"encoding/json"
	"net/http"

	"github.com/rancher/rancher/pkg/settings"
)

type OpenIDConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgsValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
}

func openIDConfigurationEndpoint(w http.ResponseWriter, r *http.Request) {
	config := OpenIDConfiguration{
		Issuer:                            oidcProviderHost(),
		AuthorizationEndpoint:             oidcProviderHost() + "/authorize",
		TokenEndpoint:                     oidcProviderHost() + "/token",
		JWKSURI:                           oidcProviderHost() + "/.well-known/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgsValuesSupported: []string{"RS256"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ScopesSupported:                   []string{"openid", "profile", "offline_access"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(&config); err != nil {
		http.Error(w, "failed to encode JWKS", http.StatusInternalServerError)
	}
}

func oidcProviderHost() string {
	return settings.ServerURL.Get() + "/oidc"
}
