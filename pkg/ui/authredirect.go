package ui

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/rancher/rancher/pkg/oidcprovider"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
)

var (
	authToTarget = map[string]string{
		"vue":   "/dashboard/auth/verify",
		"ember": "/verify",
	}
)

func redirectAuth(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	state := vars["state"]
	if strings.HasPrefix(state, "oidc-provider") {
		// redirect to OIDC provider if flow was started by the OIDC provider
		values, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			fmt.Println(err) //TODO
		}
		code := values.Get("code")
		if code == "" {
			fmt.Println("cant find code in request") //TODO
			return
		}
		// TODO using ::: as a separator is not safe!
		split := strings.SplitN(state, ":::", 3)
		http.Redirect(rw, req, oidcprovider.OIDCProviderHost()+"/authorize/callback?code="+code+"&response_type=code&redirect_uri=http://localhost:8000&client_id="+oidcprovider.ClientID+"&state="+split[1]+"&nonce="+split[2], http.StatusFound)
		return
	} else {
		bytes, err := base64.RawURLEncoding.DecodeString(vars["state"])
		if err != nil {
			emberIndexUnlessAPI().ServeHTTP(rw, req)
			return
		}

		input := struct {
			To string `json:"to,omitempty"`
		}{}
		if err := json.Unmarshal(bytes, &input); err != nil || authToTarget[input.To] == "" {
			emberIndexUnlessAPI().ServeHTTP(rw, req)
			return
		}

		u := url.URL{
			Path:     authToTarget[input.To],
			RawQuery: req.URL.RawQuery,
		}
		fmt.Println(u.String())
		http.Redirect(rw, req, u.String(), http.StatusFound)
	}
}
