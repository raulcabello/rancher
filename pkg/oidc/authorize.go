package oidc

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers"
	"github.com/rancher/rancher/pkg/auth/tokens"
	wrangmgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/oidc/session"
	"github.com/rancher/rancher/pkg/settings"
)

const (
	supportedResponseType        = "code"
	supportedCodeChallengeMethod = "S256"
)

type authParams struct {
	clientID            string
	responseType        string
	scopes              []string
	codeChallenge       string
	codeChallengeMethod string
	nonce               string
	state               string
	redirectURI         string
}

type CodeCreator interface {
	GenerateCode() (string, error)
}

type sessionAdder interface {
	Add(code string, session session.Session) error
}

type authorizeHandler struct {
	tokenCache      wrangmgmtv3.TokenCache
	userLister      wrangmgmtv3.UserCache
	oidcClientCache wrangmgmtv3.OIDCClientCache
	sessionAdder    sessionAdder
	codeCreator     CodeCreator
	now             func() time.Time
}

func newAuthorizeHandler(tokenCache wrangmgmtv3.TokenCache, userLister wrangmgmtv3.UserCache, sessionAdder sessionAdder, codeCreator CodeCreator, oidcClientCache wrangmgmtv3.OIDCClientCache) *authorizeHandler {
	return &authorizeHandler{
		tokenCache:      tokenCache,
		userLister:      userLister,
		sessionAdder:    sessionAdder,
		codeCreator:     codeCreator,
		oidcClientCache: oidcClientCache,
		now:             time.Now,
	}
}

func (h *authorizeHandler) authEndpoint(w http.ResponseWriter, r *http.Request) {
	params, err := getAuthParamsFromRequest(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("error parsing parameters from request %v", err), http.StatusBadRequest)
		return
	}
	if params.responseType != supportedResponseType {
		http.Error(w, fmt.Sprintf("invalid response type %v", params.responseType), http.StatusBadRequest)
		return
	}
	if params.codeChallengeMethod != supportedCodeChallengeMethod {
		http.Error(w, "challenge_method not supported, only S256 is supported", http.StatusBadRequest)
		return
	}
	if !slices.Contains(params.scopes, "openid") {
		http.Error(w, fmt.Sprintf("missing openid scope"), http.StatusBadRequest)
		return
	}
	if params.codeChallenge == "" {
		http.Error(w, fmt.Sprintf("missing code_challenge"), http.StatusBadRequest)
		return
	}
	if params.redirectURI == "" {
		http.Error(w, fmt.Sprintf("missing redirect_uri"), http.StatusBadRequest)
		return
	}
	oidcClients, err := h.oidcClientCache.GetByIndex("oidc.management.cattle.io/oidcclient-by-id", params.clientID) //TODO index const?
	if err != nil {
		http.Error(w, fmt.Sprintf("error retreiving OIDC client: %v", err), http.StatusBadRequest)
		return
	}
	if len(oidcClients) == 0 {
		http.Error(w, fmt.Sprintf("no OIDC client found: %v", err), http.StatusBadRequest)
		return
	}
	oidcClient := oidcClients[0]

	if !slices.Contains(oidcClient.Spec.RedirectURIs, params.redirectURI) {
		http.Error(w, fmt.Sprintf("redirect_uri %s is not registered", params.redirectURI), http.StatusBadRequest)
		return
	}
	token, err := h.getAndVerifyRancherTokenFromRequest(r)
	if err != nil {
		// TODO improve
		http.Redirect(w, r, settings.ServerURL.Get()+"/dashboard/auth/login?client_id="+r.URL.Query().Get("client_id")+"&redirect_uri="+r.URL.Query().Get("redirect_uri")+"&response_type=code&scope="+r.URL.Query().Get("scope")+"&state="+r.URL.Query().Get("state")+"&nonce="+r.URL.Query().Get("nonce")+"&code_challenge="+r.URL.Query().Get("code_challenge"), http.StatusFound) // TODO scope!
		return
	}

	code, err := h.codeCreator.GenerateCode()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate code: %v", err), http.StatusBadRequest)
		return
	}

	err = h.sessionAdder.Add(code, session.Session{
		ClientID:      params.clientID,
		TokenName:     token.Name,
		Scope:         params.scopes,
		CodeChallenge: params.codeChallenge,
		Nonce:         params.nonce,
		CreatedAt:     h.now(),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, params.redirectURI+"?code="+code+"&state="+params.state, http.StatusFound)
}

func (h *authorizeHandler) getAndVerifyRancherTokenFromRequest(r *http.Request) (*v3.Token, error) {
	tokenAuthValue := tokens.GetTokenAuthFromRequest(r)
	if tokenAuthValue == "" {
		return nil, fmt.Errorf("rancher token not present")
	}
	tokenName, tokenKey := tokens.SplitTokenParts(tokenAuthValue)
	if tokenName == "" || tokenKey == "" {
		return nil, fmt.Errorf("can't split rancher token")

	}
	token, err := h.tokenCache.Get(tokenName)
	if err != nil {
		return nil, fmt.Errorf("can't get token: %v", err)
	}
	if token.Token != tokenKey {
		return nil, fmt.Errorf("token doesn't match")
	}
	if token.Enabled != nil && !*token.Enabled {
		return nil, fmt.Errorf("token not enabled")
	}

	// If the auth provider is specified make sure it exists and enabled.
	if token.AuthProvider != "" {
		disabled, err := providers.IsDisabledProvider(token.AuthProvider)
		if err != nil {
			return nil, fmt.Errorf("can't check if auth provider is disabled: %v", err)
		}
		if disabled {
			return nil, fmt.Errorf("auth provider is disabled")
		}
	}

	authUser, err := h.userLister.Get(token.UserID)
	if err != nil {
		return nil, fmt.Errorf("can't get user: %v", err)
	}

	if authUser.Enabled != nil && !*authUser.Enabled {
		return nil, fmt.Errorf("user is disabled")
	}

	return token, nil
}

func getAuthParamsFromRequest(r *http.Request) (*authParams, error) {
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			return nil, err
		}
		return &authParams{
			clientID:            r.Form.Get("client_id"),
			scopes:              strings.Split(r.Form.Get("scope"), " "),
			codeChallenge:       r.Form.Get("code_challenge"),
			codeChallengeMethod: r.Form.Get("code_challenge_method"),
			nonce:               r.Form.Get("nonce"),
			state:               r.Form.Get("state"),
			redirectURI:         r.Form.Get("redirect_uri"),
			responseType:        r.Form.Get("response_type"),
		}, nil
	}
	if r.Method == "GET" {
		return &authParams{
			clientID:            r.URL.Query().Get("client_id"),
			scopes:              strings.Split(r.URL.Query().Get("scope"), " "),
			codeChallenge:       r.URL.Query().Get("code_challenge"),
			codeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
			nonce:               r.URL.Query().Get("nonce"),
			state:               r.URL.Query().Get("state"),
			redirectURI:         r.URL.Query().Get("redirect_uri"),
			responseType:        r.URL.Query().Get("response_type"),
		}, nil
	}

	return nil, fmt.Errorf("unsupported method")
}
