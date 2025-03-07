package oidc_integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	goidc "github.com/coreos/go-oidc/v3/oidc"
	gmux "github.com/gorilla/mux"
	apimgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers"
	providermocks "github.com/rancher/rancher/pkg/auth/providers/mocks"
	"github.com/rancher/rancher/pkg/auth/tokens"
	"github.com/rancher/rancher/pkg/oidc"
	"github.com/rancher/rancher/pkg/oidc/token"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/rancher/pkg/wrangler"
	"github.com/rancher/rancher/tests/controllers/common"
	"github.com/rancher/wrangler/v3/pkg/crd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
	"io/ioutil"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"testing"
	"time"
)

type OIDCProviderSuite struct {
	suite.Suite
	ctx             context.Context
	cancel          context.CancelFunc
	testEnv         *envtest.Environment
	wranglerContext *wrangler.Context
	server          *httptest.Server
	providerURL     string
}

// Replace with your OIDC provider settings
const (
	clientID     = "oidc-client"
	clientSecret = "BimPY6GrQCX2cYPJi3b1jxxAlci"
)

var (
	provider     *goidc.Provider
	oauth2Config oauth2.Config
	verifier     *goidc.IDTokenVerifier
	codeVerifier string
)

func (s *OIDCProviderSuite) redirect(rw http.ResponseWriter, r *http.Request) {
	oauth2Token, err := oauth2Config.Exchange(context.TODO(), r.URL.Query().Get("code"), oauth2.VerifierOption(codeVerifier))
	assert.NoError(s.T(), err)

	tokenResponse := token.TokenResponse{
		IDToken:      oauth2Token.Extra("id_token").(string),
		AccessToken:  oauth2Token.AccessToken,
		RefreshToken: oauth2Token.RefreshToken,
	}
	rw.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(rw).Encode(&tokenResponse); err != nil {
		assert.NoError(s.T(), err)
	}
}

func (s *OIDCProviderSuite) SetupSuite() {
	s.ctx, s.cancel = context.WithCancel(context.TODO())

	// Start envtest
	s.testEnv = &envtest.Environment{}
	restCfg, err := s.testEnv.Start()
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), restCfg)

	// Register CRDs
	common.RegisterCRDs(s.ctx, s.T(), restCfg,
		crd.CRD{
			SchemaObject: apimgmtv3.Token{},
			NonNamespace: true,
		},
		crd.CRD{
			SchemaObject: apimgmtv3.User{},
			NonNamespace: true,
		},
	)

	// Create wrangler context
	s.wranglerContext, err = wrangler.NewContext(s.ctx, nil, restCfg)
	assert.NoError(s.T(), err)

	// Init caches
	_, err = s.wranglerContext.ControllerFactory.SharedCacheFactory().ForKind(schema.GroupVersionKind{
		Group:   "management.cattle.io",
		Version: "v3",
		Kind:    "Token",
	})
	assert.NoError(s.T(), err)
	_, err = s.wranglerContext.ControllerFactory.SharedCacheFactory().ForKind(schema.GroupVersionKind{
		Group:   "management.cattle.io",
		Version: "v3",
		Kind:    "User",
	})
	assert.NoError(s.T(), err)

	_, err = s.wranglerContext.ControllerFactory.SharedCacheFactory().ForKind(schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Secret",
	})
	assert.NoError(s.T(), err)

	// Start caches
	common.StartWranglerCaches(s.ctx, s.T(), s.wranglerContext,
		schema.GroupVersionKind{
			Group:   "management.cattle.io",
			Version: "v3",
			Kind:    "Token",
		},
		schema.GroupVersionKind{
			Group:   "management.cattle.io",
			Version: "v3",
			Kind:    "User",
		},
		schema.GroupVersionKind{
			Group:   "",
			Version: "v1",
			Kind:    "Secret",
		})

	s.wranglerContext.ControllerFactory.SharedCacheFactory().WaitForCacheSync(context.TODO())

	_, err = s.wranglerContext.Core.Namespace().Create(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cattle-system",
		},
	})
	assert.NoError(s.T(), err)

	// init OIDC provider
	mux := gmux.NewRouter()
	mux.UseEncodedPath()

	p, err := oidc.NewProvider(context.TODO(), s.wranglerContext.Mgmt.Token().Cache(), s.wranglerContext.Mgmt.Token(), s.wranglerContext.Mgmt.User().Cache(), s.wranglerContext.Mgmt.UserAttribute().Cache(), s.wranglerContext.Core.Secret().Cache(), s.wranglerContext.Core.Secret(), s.wranglerContext.Mgmt.OIDCClient().Cache(), s.wranglerContext.Mgmt.OIDCClient())
	assert.NoError(s.T(), err)

	p.RegisterOIDCProviderHandles(mux)

	mux.HandleFunc("/redirect", s.redirect)

	s.server = httptest.NewServer(mux)
}

func (s *OIDCProviderSuite) TearDownSuite() {
	s.server.Close()
	s.cancel()
	err := s.testEnv.Stop()
	assert.NoError(s.T(), err)
}

const (
	fakeTokenName    = "fake-token-name"
	fakeTokenValue   = "fake-token-value"
	fakeUserID       = "fake-user-id"
	fakeCode         = "fake-code"
	fakeClientSecret = "fake-client-secret"
)

func (s *OIDCProviderSuite) TestLogin() {
	ctrl := gomock.NewController(s.T())
	_, err := s.wranglerContext.Mgmt.User().Create(&apimgmtv3.User{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-user",
		},
	})
	assert.NoError(s.T(), err)
	_, err = s.wranglerContext.Mgmt.Token().Create(&apimgmtv3.Token{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-token-name",
			Labels: map[string]string{
				tokens.UserIDLabel: "fake-user",
			},
		},
		AuthProvider: "auth-provider",
		Token:        "fake-token-value",
		UserID:       "fake-user",
		Enabled:      ptr.To(true),
	})
	assert.NoError(s.T(), err)

	_, err = s.wranglerContext.Core.Namespace().Create(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cattle-oidc-clients",
		},
	})
	assert.NoError(s.T(), err)

	err = s.wranglerContext.Mgmt.OIDCClient().Informer().GetIndexer().Add(&v3.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: "oidc-client",
		},
		Spec: v3.OIDCClientSpec{
			RedirectURIs: []string{s.server.URL + "/redirect"},
		},
		Status: v3.OIDCClientStatus{
			ClientID: clientID,
		},
	})
	assert.NoError(s.T(), err)
	_, err = s.wranglerContext.Core.Secret().Create(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clientID,
			Namespace: "cattle-oidc-clients",
		},
		Data: map[string][]byte{ //TODO check!
			"client-secret": []byte(clientSecret),
		},
	})
	assert.NoError(s.T(), err)

	mockProvider := providermocks.NewMockAuthProvider(ctrl)
	mockProvider.EXPECT().IsDisabledProvider().Return(false, nil).AnyTimes()
	providers.Providers["auth-provider"] = mockProvider

	s.wranglerContext.ControllerFactory.SharedCacheFactory().WaitForCacheSync(context.TODO())
	time.Sleep(1 * time.Second)
	t, err := s.wranglerContext.Mgmt.Token().Cache().Get("fake-token-name")
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "fake-user", t.UserID)

	err = settings.ServerURL.Set(s.server.URL)
	assert.NoError(s.T(), err)

	provider, err = goidc.NewProvider(context.TODO(), s.server.URL+"/oidc")
	assert.NoError(s.T(), err)

	// Configure OAuth2 client
	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  s.server.URL + "/redirect",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{goidc.ScopeOpenID, "profile", "offline_access"},
	}

	// Create an ID token verifier
	verifier = provider.Verifier(&goidc.Config{ClientID: clientID})
	authURL := oauth2Config.AuthCodeURL("12345678910", oauth2.S256ChallengeOption(codeVerifier))

	req, err := http.NewRequest("GET", authURL, nil)
	assert.NoError(s.T(), err)
	req.Header.Set("Authorization", "Bearer fake-token-name:fake-token-value")
	client := &http.Client{}
	res, err := client.Do(req)
	defer res.Body.Close()
	assert.NoError(s.T(), err)
	//b, _ := ioutil.ReadAll(res.Body)
	//fmt.Println(b)
	var tokenResponse *token.TokenResponse
	err = json.NewDecoder(res.Body).Decode(&tokenResponse)
	assert.NoError(s.T(), err)

	idToken, err := verifier.Verify(context.TODO(), tokenResponse.IDToken)
	assert.NoError(s.T(), err)

	assert.Equal(s.T(), []string{"oidc-client"}, idToken.Audience)
	assert.Equal(s.T(), "fake-user", idToken.Subject)

	//refresh token
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", tokenResponse.RefreshToken)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err = http.NewRequest("POST", provider.Endpoint().TokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		fmt.Printf("Failed to create HTTP request: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client = &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Failed to send HTTP request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("Failed to refresh token: %s\nResponse: %s\n", resp.Status, string(body))
		return
	}

	//	body, _ := ioutil.ReadAll(resp.Body)
	//	fmt.Printf("Refresh token: %s\n", string(body))

	var refreshTokenResponse *token.TokenResponse
	err = json.NewDecoder(resp.Body).Decode(&refreshTokenResponse)
	assert.NoError(s.T(), err)

	assert.NotNil(s.T(), refreshTokenResponse.AccessToken)
	assert.NotNil(s.T(), refreshTokenResponse.IDToken)
	assert.NotNil(s.T(), refreshTokenResponse.RefreshToken)

}

func TestOIDCProviderSuite(t *testing.T) {
	suite.Run(t, new(OIDCProviderSuite))
}
