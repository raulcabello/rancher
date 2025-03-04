//go:generate mockgen -source=auth.go -destination=../mocks/auth.go -package=mocks
//go:generate mockgen -source=../session/session.go -destination=../mocks/session.go -package=mocks

package auth

import (
	"encoding/json"
	extv1 "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/ext/oidcclients"
	wrangmgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/oidc/mocks"
	"github.com/rancher/rancher/pkg/oidc/session"
	corecontrollers "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestAuthEndpoint(t *testing.T) {
	const (
		fakeTokenName   = "fake-token-name"
		fakeTokenValue  = "fake-token-value"
		fakeUserID      = "fake-user-id"
		fakeCode        = "fake-code"
		fakeRedirectUri = "https://www.rancher.com"
		fakeClientID    = "client-id"
	)
	fakeTime := time.Unix(0, 0)
	ctrl := gomock.NewController(t)
	tests := map[string]struct {
		req          func() *http.Request
		tokenCache   func() wrangmgmtv3.TokenCache
		secretCache  func() corecontrollers.SecretCache
		userLister   func() wrangmgmtv3.UserCache
		storage      func() session.Storage
		codeCreator  func() CodeCreator
		wantRedirect string
		wantHttpCode int
		wantError    string
	}{
		"redirect with code when Rancher token in present": {
			tokenCache: func() wrangmgmtv3.TokenCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl)
				mock.EXPECT().Get(fakeTokenName).Return(&v3.Token{
					ObjectMeta: metav1.ObjectMeta{
						Name: fakeTokenName,
					},
					Token:  fakeTokenValue,
					UserID: fakeUserID,
				}, nil)
				return mock
			},
			secretCache: func() corecontrollers.SecretCache {
				mock := fake.NewMockCacheInterface[*v1.Secret](ctrl)
				c := extv1.OIDCClient{
					Spec: extv1.OIDCClientSpec{
						RedirectURIs: []string{fakeRedirectUri},
					},
				}
				jsonBytes, err := json.Marshal(&c)
				mock.EXPECT().Get("cattle-oidc-clients", fakeClientID).Return(&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: fakeClientID,
					},
					Data: map[string][]byte{
						"oidc-client": jsonBytes,
					},
				}, err)
				return mock
			},
			userLister: func() wrangmgmtv3.UserCache {
				mock := fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
				mock.EXPECT().Get(fakeUserID).Return(&v3.User{
					ObjectMeta: metav1.ObjectMeta{
						Name: fakeUserID,
					},
				}, nil)

				return mock
			},
			storage: func() session.Storage {
				mock := mocks.NewMockStorage(ctrl)
				mock.EXPECT().AddSession(fakeCode, session.Session{
					ClientID:      fakeClientID,
					TokenName:     fakeTokenName,
					Scope:         []string{"openid"},
					CodeChallenge: "code-challenge",
					CreatedAt:     fakeTime,
				})

				return mock
			},
			req: func() *http.Request {
				req := &http.Request{
					URL: &url.URL{
						Scheme:   "https",
						Host:     "rancher.com",
						RawQuery: "code_challenge_method=S256&response_type=code&code_challenge=code-challenge&client_id=client-id&scope=openid&redirect_uri=" + fakeRedirectUri,
					},
					Method: http.MethodGet,
				}
				req.Header = map[string][]string{
					"Cookie": {"R_SESS=" + fakeTokenName + ":" + fakeTokenValue},
				}

				return req
			},
			codeCreator: func() CodeCreator {
				mock := mocks.NewMockCodeCreator(ctrl)
				mock.EXPECT().GenerateCode().Return(fakeCode, nil)
				return mock
			},
			wantHttpCode: http.StatusFound,
			wantRedirect: fakeRedirectUri + "?code=fake-code&state=",
		},
		"redirect to login page if Rancher token is not present": {
			req: func() *http.Request {
				return &http.Request{
					URL: &url.URL{
						Scheme:   "https",
						Host:     "rancher.com",
						RawQuery: "code_challenge_method=S256&code_challenge=code-challenge&response_type=code&redirect_uri=https://www.rancher.com&scope=openid&client_id=client-id",
					},
					Method: http.MethodGet,
				}
			},
			tokenCache: func() wrangmgmtv3.TokenCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl)
			},
			userLister: func() wrangmgmtv3.UserCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
			},
			storage: func() session.Storage {
				return &session.MemoryStorage{}
			},
			secretCache: func() corecontrollers.SecretCache {
				mock := fake.NewMockCacheInterface[*v1.Secret](ctrl)
				c := extv1.OIDCClient{
					Spec: extv1.OIDCClientSpec{
						RedirectURIs: []string{fakeRedirectUri},
					},
				}
				jsonBytes, err := json.Marshal(&c)
				mock.EXPECT().Get("cattle-oidc-clients", fakeClientID).Return(&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: fakeClientID,
					},
					Data: map[string][]byte{
						"oidc-client": jsonBytes,
					},
				}, err)
				return mock
			},
			codeCreator: func() CodeCreator {
				return mocks.NewMockCodeCreator(ctrl)
			},
			wantHttpCode: http.StatusFound,
			wantRedirect: "/dashboard/auth/login?client_id=client-id&redirect_uri=https://www.rancher.com&response_type=code&scope=openid&state=&nonce=&code_challenge=code-challenge",
		},
		"response type not supported": {
			tokenCache: func() wrangmgmtv3.TokenCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl)
			},
			secretCache: func() corecontrollers.SecretCache {
				return fake.NewMockCacheInterface[*v1.Secret](ctrl)
			},
			userLister: func() wrangmgmtv3.UserCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
			},
			storage: func() session.Storage {
				return mocks.NewMockStorage(ctrl)
			},
			req: func() *http.Request {
				req := &http.Request{
					URL: &url.URL{
						Scheme:   "https",
						Host:     "rancher.com",
						RawQuery: "code_challenge_method=S256&response_type=none&code_challenge=code-challenge&client_id=client-id&scope=openid&redirect_uri=" + fakeRedirectUri,
					},
					Method: http.MethodGet,
				}
				req.Header = map[string][]string{
					"Cookie": {"R_SESS=" + fakeTokenName + ":" + fakeTokenValue},
				}

				return req
			},
			codeCreator: func() CodeCreator {
				return mocks.NewMockCodeCreator(ctrl)
			},
			wantHttpCode: http.StatusBadRequest,
			wantError:    "invalid response type none\n",
		},
		"code challenge method not supported": {
			tokenCache: func() wrangmgmtv3.TokenCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl)
			},
			secretCache: func() corecontrollers.SecretCache {
				return fake.NewMockCacheInterface[*v1.Secret](ctrl)
			},
			userLister: func() wrangmgmtv3.UserCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
			},
			storage: func() session.Storage {
				return mocks.NewMockStorage(ctrl)
			},
			req: func() *http.Request {
				req := &http.Request{
					URL: &url.URL{
						Scheme:   "https",
						Host:     "rancher.com",
						RawQuery: "code_challenge_method=plain&response_type=code&code_challenge=code-challenge&client_id=client-id&scope=openid&redirect_uri=" + fakeRedirectUri,
					},
					Method: http.MethodGet,
				}
				req.Header = map[string][]string{
					"Cookie": {"R_SESS=" + fakeTokenName + ":" + fakeTokenValue},
				}

				return req
			},
			codeCreator: func() CodeCreator {
				return mocks.NewMockCodeCreator(ctrl)
			},
			wantHttpCode: http.StatusBadRequest,
			wantError:    "challenge_method not supported, only S256 is supported\n",
		},
		"missing openid": {
			tokenCache: func() wrangmgmtv3.TokenCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl)
			},
			secretCache: func() corecontrollers.SecretCache {
				return fake.NewMockCacheInterface[*v1.Secret](ctrl)
			},
			userLister: func() wrangmgmtv3.UserCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
			},
			storage: func() session.Storage {
				return mocks.NewMockStorage(ctrl)
			},
			req: func() *http.Request {
				req := &http.Request{
					URL: &url.URL{
						Scheme:   "https",
						Host:     "rancher.com",
						RawQuery: "code_challenge_method=S256&response_type=code&code_challenge=code-challenge&client_id=client-id&scope=profile&redirect_uri=" + fakeRedirectUri,
					},
					Method: http.MethodGet,
				}
				req.Header = map[string][]string{
					"Cookie": {"R_SESS=" + fakeTokenName + ":" + fakeTokenValue},
				}

				return req
			},
			codeCreator: func() CodeCreator {
				return mocks.NewMockCodeCreator(ctrl)
			},
			wantHttpCode: http.StatusBadRequest,
			wantError:    "missing openid scope\n",
		},
		"missing code challenge": {
			tokenCache: func() wrangmgmtv3.TokenCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl)
			},
			secretCache: func() corecontrollers.SecretCache {
				return fake.NewMockCacheInterface[*v1.Secret](ctrl)
			},
			userLister: func() wrangmgmtv3.UserCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
			},
			storage: func() session.Storage {
				return mocks.NewMockStorage(ctrl)
			},
			req: func() *http.Request {
				req := &http.Request{
					URL: &url.URL{
						Scheme:   "https",
						Host:     "rancher.com",
						RawQuery: "code_challenge_method=S256&response_type=code&client_id=client-id&scope=profile&redirect_uri=" + fakeRedirectUri,
					},
					Method: http.MethodGet,
				}
				req.Header = map[string][]string{
					"Cookie": {"R_SESS=" + fakeTokenName + ":" + fakeTokenValue},
				}

				return req
			},
			codeCreator: func() CodeCreator {
				return mocks.NewMockCodeCreator(ctrl)
			},
			wantHttpCode: http.StatusBadRequest,
			wantError:    "missing code challenge\n",
		},
		"missing redirect uri": {
			tokenCache: func() wrangmgmtv3.TokenCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl)
			},
			secretCache: func() corecontrollers.SecretCache {
				return fake.NewMockCacheInterface[*v1.Secret](ctrl)
			},
			userLister: func() wrangmgmtv3.UserCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
			},
			storage: func() session.Storage {
				return mocks.NewMockStorage(ctrl)
			},
			req: func() *http.Request {
				req := &http.Request{
					URL: &url.URL{
						Scheme:   "https",
						Host:     "rancher.com",
						RawQuery: "code_challenge_method=S256&response_type=code&code_challenge=code-challenge&client_id=client-id&scope=profile&redirect_uri=" + fakeRedirectUri,
					},
					Method: http.MethodGet,
				}
				req.Header = map[string][]string{
					"Cookie": {"R_SESS=" + fakeTokenName + ":" + fakeTokenValue},
				}

				return req
			},
			codeCreator: func() CodeCreator {
				return mocks.NewMockCodeCreator(ctrl)
			},
			wantHttpCode: http.StatusBadRequest,
			wantError:    "missing openid scope\n",
		},
		"oidc client not registered": {
			tokenCache: func() wrangmgmtv3.TokenCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl)
			},
			secretCache: func() corecontrollers.SecretCache {
				mock := fake.NewMockCacheInterface[*v1.Secret](ctrl)
				mock.EXPECT().Get("cattle-oidc-clients", fakeClientID).Return(nil, errors.NewNotFound(schema.GroupResource{}, fakeClientID))
				return mock
			},
			userLister: func() wrangmgmtv3.UserCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
			},
			storage: func() session.Storage {
				return mocks.NewMockStorage(ctrl)
			},
			req: func() *http.Request {
				req := &http.Request{
					URL: &url.URL{
						Scheme:   "https",
						Host:     "rancher.com",
						RawQuery: "code_challenge_method=S256&response_type=code&code_challenge=code-challenge&client_id=client-id&scope=openid&redirect_uri=" + fakeRedirectUri,
					},
					Method: http.MethodGet,
				}
				req.Header = map[string][]string{
					"Cookie": {"R_SESS=" + fakeTokenName + ":" + fakeTokenValue},
				}

				return req
			},
			codeCreator: func() CodeCreator {
				return mocks.NewMockCodeCreator(ctrl)
			},
			wantHttpCode: http.StatusBadRequest,
			wantError:    "error retreiving OIDC client:  \"client-id\" not found\n",
		},
		"redirect uri not registed": {
			tokenCache: func() wrangmgmtv3.TokenCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl)
			},
			secretCache: func() corecontrollers.SecretCache {
				mock := fake.NewMockCacheInterface[*v1.Secret](ctrl)
				c := extv1.OIDCClient{
					Spec: extv1.OIDCClientSpec{
						RedirectURIs: []string{"anotherRedirect"},
					},
				}
				jsonBytes, err := json.Marshal(&c)
				mock.EXPECT().Get("cattle-oidc-clients", fakeClientID).Return(&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: fakeClientID,
					},
					Data: map[string][]byte{
						"oidc-client": jsonBytes,
					},
				}, err)
				return mock
			},
			userLister: func() wrangmgmtv3.UserCache {
				return fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
			},
			storage: func() session.Storage {
				return mocks.NewMockStorage(ctrl)
			},
			req: func() *http.Request {
				req := &http.Request{
					URL: &url.URL{
						Scheme:   "https",
						Host:     "rancher.com",
						RawQuery: "code_challenge_method=S256&response_type=code&code_challenge=code-challenge&client_id=client-id&scope=openid&redirect_uri=" + fakeRedirectUri,
					},
					Method: http.MethodGet,
				}
				req.Header = map[string][]string{
					"Cookie": {"R_SESS=" + fakeTokenName + ":" + fakeTokenValue},
				}

				return req
			},
			codeCreator: func() CodeCreator {
				return mocks.NewMockCodeCreator(ctrl)
			},
			wantHttpCode: http.StatusBadRequest,
			wantError:    "redirect_uri https://www.rancher.com is not registered\n",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := NewHandler(test.tokenCache(), test.userLister(), test.storage(), test.codeCreator(), oidcclients.NewStoreCache(test.secretCache()))
			h.now = func() time.Time {
				return fakeTime
			}
			rec := httptest.NewRecorder()

			h.AuthEndpoint(rec, test.req())

			assert.Equal(t, test.wantHttpCode, rec.Code)
			if test.wantRedirect != "" {
				assert.Equal(t, test.wantRedirect, rec.Header().Get("Location"))
			}
			if test.wantError != "" {
				assert.Equal(t, test.wantError, rec.Body.String())
			}
		})
	}
}
