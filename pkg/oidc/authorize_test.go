//go:generate mockgen -source=auth.go -destination=../mocks/auth.go -package=mocks
//go:generate mockgen -source=../session/session.go -destination=../mocks/session.go -package=mocks

package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/oidc/mocks"
	"github.com/rancher/rancher/pkg/oidc/session"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestAuthEndpoint(t *testing.T) {
	const (
		fakeTokenName   = "fake-token-name"
		fakeTokenValue  = "fake-token-value"
		fakeUserID      = "fake-user-id"
		fakeCode        = "fake-code"
		fakeRedirectUri = "https://www.rancher.com"
		fakeClientID    = "client-id"
		fakeClientName  = "client-name"
	)
	type mockParams struct {
		tokenCache      *fake.MockNonNamespacedCacheInterface[*v3.Token]
		userLister      *fake.MockNonNamespacedCacheInterface[*v3.User]
		oidcClientCache *fake.MockNonNamespacedCacheInterface[*v3.OIDCClient]
		codeCreator     *mocks.MockCodeCreator
		storage         *mocks.MockStorage
	}
	fakeTime := time.Unix(0, 0)
	ctrl := gomock.NewController(t)
	tests := map[string]struct {
		req          func() *http.Request
		mockSetup    func(mockParams)
		wantRedirect string
		wantHttpCode int
		wantError    string
	}{
		"redirect with code when Rancher token in present": {
			mockSetup: func(m mockParams) {
				m.tokenCache.EXPECT().Get(fakeTokenName).Return(&v3.Token{
					ObjectMeta: metav1.ObjectMeta{
						Name: fakeTokenName,
					},
					Token:  fakeTokenValue,
					UserID: fakeUserID,
				}, nil)
				m.userLister.EXPECT().Get(fakeUserID).Return(&v3.User{
					ObjectMeta: metav1.ObjectMeta{
						Name: fakeUserID,
					},
				}, nil)
				m.storage.EXPECT().AddSession(fakeCode, session.Session{
					ClientID:      fakeClientID,
					TokenName:     fakeTokenName,
					Scope:         []string{"openid"},
					CodeChallenge: "code-challenge",
					CreatedAt:     fakeTime,
				})
				m.oidcClientCache.EXPECT().GetByIndex("oidc.management.cattle.io/oidcclient-by-id", fakeClientID).Return([]*v3.OIDCClient{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: fakeClientName,
						},
						Spec: v3.OIDCClientSpec{
							RedirectURIs: []string{fakeRedirectUri},
						},
						Status: v3.OIDCClientStatus{
							ClientID: fakeClientID,
						},
					},
				}, nil)
				m.codeCreator.EXPECT().GenerateCode().Return(fakeCode, nil)
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
			mockSetup: func(m mockParams) {
				m.oidcClientCache.EXPECT().GetByIndex("oidc.management.cattle.io/oidcclient-by-id", fakeClientID).Return([]*v3.OIDCClient{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: fakeClientName,
						},
						Spec: v3.OIDCClientSpec{
							RedirectURIs: []string{fakeRedirectUri},
						},
						Status: v3.OIDCClientStatus{
							ClientID: fakeClientID,
						},
					},
				}, nil)
			},
			wantHttpCode: http.StatusFound,
			wantRedirect: "/dashboard/auth/login?client_id=client-id&redirect_uri=https://www.rancher.com&response_type=code&scope=openid&state=&nonce=&code_challenge=code-challenge",
		},
		"response type not supported": {
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
			wantHttpCode: http.StatusBadRequest,
			wantError:    "invalid response type none\n",
		},
		"code challenge method not supported": {
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
			wantHttpCode: http.StatusBadRequest,
			wantError:    "challenge_method not supported, only S256 is supported\n",
		},
		"missing openid": {
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
			wantHttpCode: http.StatusBadRequest,
			wantError:    "missing openid scope\n",
		},
		"missing code challenge": {
			req: func() *http.Request {
				req := &http.Request{
					URL: &url.URL{
						Scheme:   "https",
						Host:     "rancher.com",
						RawQuery: "code_challenge_method=S256&response_type=code&client_id=client-id&scope=openid&redirect_uri=" + fakeRedirectUri,
					},
					Method: http.MethodGet,
				}
				req.Header = map[string][]string{
					"Cookie": {"R_SESS=" + fakeTokenName + ":" + fakeTokenValue},
				}

				return req
			},
			wantHttpCode: http.StatusBadRequest,
			wantError:    "missing code_challenge\n",
		},
		"missing redirect uri": {
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
			wantHttpCode: http.StatusBadRequest,
			wantError:    "missing openid scope\n",
		},
		"oidc client not registered": {
			mockSetup: func(m mockParams) {
				m.oidcClientCache.EXPECT().GetByIndex("oidc.management.cattle.io/oidcclient-by-id", fakeClientID).Return(nil, errors.NewNotFound(schema.GroupResource{}, fakeClientID))
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
			wantHttpCode: http.StatusBadRequest,
			wantError:    "error retreiving OIDC client:  \"client-id\" not found\n",
		},
		"redirect uri not registed": {
			mockSetup: func(m mockParams) {
				m.oidcClientCache.EXPECT().GetByIndex("oidc.management.cattle.io/oidcclient-by-id", fakeClientID).Return([]*v3.OIDCClient{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: fakeClientName,
						},
						Spec: v3.OIDCClientSpec{
							RedirectURIs: []string{"anotherurl"},
						},
						Status: v3.OIDCClientStatus{
							ClientID: fakeClientID,
						},
					},
				}, nil)
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
			wantHttpCode: http.StatusBadRequest,
			wantError:    "redirect_uri https://www.rancher.com is not registered\n",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := mockParams{
				tokenCache:      fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl),
				userLister:      fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl),
				oidcClientCache: fake.NewMockNonNamespacedCacheInterface[*v3.OIDCClient](ctrl),
				storage:         mocks.NewMockStorage(ctrl),
				codeCreator:     mocks.NewMockCodeCreator(ctrl),
			}
			if test.mockSetup != nil {
				test.mockSetup(m)
			}
			h := newAuthorizeHandler(m.tokenCache, m.userLister, m.storage, m.codeCreator, m.oidcClientCache)
			h.now = func() time.Time {
				return fakeTime
			}
			rec := httptest.NewRecorder()

			h.authEndpoint(rec, test.req())

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
