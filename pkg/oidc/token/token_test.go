//go:generate mockgen -source=../../auth/providers/common/provider.go -destination=../../auth/providers/mocks/provider.go -package=mocks

package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	extv1 "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers"
	providermocks "github.com/rancher/rancher/pkg/auth/providers/mocks"
	"github.com/rancher/rancher/pkg/ext/oidcclients"
	wrangmgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/oidc/mocks"

	"github.com/rancher/rancher/pkg/oidc/session"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestTokenEndpoint(t *testing.T) {
	ctrl := gomock.NewController(t)
	const (
		fakeCode         = "code123"
		fakeClientID     = "client-id"
		fakeClientSecret = "client-secret"
		fakeCodeVerifier = "code-verifier"
		fakeTokenName    = "token-name"
		fakeUserID       = "user-id"
		fakeAuthProvider = "auth-provider"
	)
	type mockParams struct {
		tokenCache         *fake.MockNonNamespacedCacheInterface[*v3.Token]
		secretCache        *fake.MockCacheInterface[*v1.Secret]
		userLister         wrangmgmtv3.UserCache
		useAttributeLister wrangmgmtv3.UserAttributeCache
		storage            *mocks.MockStorage
		signingKeyGetter   signingKeyGetter
	}

	tests := map[string]struct {
		req               func() *http.Request
		mockSetup         func(mockParams)
		wantTokenResponse *TokenResponse
		wantError         string
	}{
		"authorization_code creates an id_token and access_token": {
			req: func() *http.Request {
				data := url.Values{}
				data.Set("grant_type", "authorization_code")
				data.Set("code", fakeCode)
				data.Set("code_verifier", fakeCodeVerifier)
				req, _ := http.NewRequest("POST", "https://rancher.com", bytes.NewBufferString(data.Encode()))
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Add("Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fakeClientID+":"+fakeClientSecret))))

				return req
			},
			mockSetup: func(m mockParams) {
				m.storage.EXPECT().GetAndRemoveSession(fakeCode).Return(session.Session{
					ClientID:      fakeClientID,
					TokenName:     fakeTokenName,
					Scope:         nil,
					CodeChallenge: oauth2.S256ChallengeFromVerifier(fakeCodeVerifier),
					Nonce:         "",
				}, nil)
				oidcClient := extv1.OIDCClient{
					ObjectMeta: metav1.ObjectMeta{
						Name: fakeClientID,
					},
					Spec: extv1.OIDCClientSpec{
						Secret: fakeClientSecret,
					},
				}
				jsonBytes, _ := json.Marshal(oidcClient)
				m.secretCache.EXPECT().Get("cattle-oidc-clients", fakeClientID).Return(&v1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: fakeClientID,
					},
					Data: map[string][]byte{
						"oidc-client": jsonBytes,
					},
				}, nil)

				m.tokenCache.EXPECT().Get(fakeTokenName).Return(&v3.Token{
					UserID:       fakeUserID,
					Enabled:      ptr.To(true),
					AuthProvider: fakeAuthProvider,
				}, nil)

				//register auth provider
				mockProvider := providermocks.NewMockAuthProvider(ctrl)
				mockProvider.EXPECT().IsDisabledProvider().Return(false, nil)
				providers.Providers[fakeAuthProvider] = mockProvider
			},
			wantTokenResponse: &TokenResponse{}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := mockParams{
				tokenCache:         fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl),
				secretCache:        fake.NewMockCacheInterface[*v1.Secret](ctrl),
				userLister:         fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl),
				useAttributeLister: fake.NewMockNonNamespacedCacheInterface[*v3.UserAttribute](ctrl),
				storage:            mocks.NewMockStorage(ctrl),
			}
			if test.mockSetup != nil {
				test.mockSetup(m)
			}
			h := NewHandler(m.tokenCache, m.userLister, m.useAttributeLister, m.storage, m.signingKeyGetter, oidcclients.NewStoreCache(m.secretCache))

			rec := httptest.NewRecorder()

			h.TokenEndpoint(rec, test.req())

			if test.wantError != "" {
				assert.Equal(t, test.wantError, rec.Body.String())
			}
			if test.wantTokenResponse != nil {
				var tokenResponse TokenResponse
				err := json.Unmarshal(rec.Body.Bytes(), &tokenResponse)
				assert.NoError(t, err)
				assert.Equal(t, test.wantTokenResponse, &tokenResponse)
			}

		})
	}
}
