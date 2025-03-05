//go:generate mockgen -source=../../auth/providers/common/provider.go -destination=../../auth/providers/mocks/provider.go -package=mocks
//go:generate mockgen -source=./token.go -destination=../mocks/token.go -package=mocks

package token

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	extv1 "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers"
	providermocks "github.com/rancher/rancher/pkg/auth/providers/mocks"
	"github.com/rancher/rancher/pkg/ext/oidcclients"
	"github.com/rancher/rancher/pkg/oidc/mocks"
	"github.com/rancher/rancher/pkg/settings"
	"time"

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
		fakeUsername     = "username"
		fakeGroup        = "group"
		fakeSigningKey   = "key"
		fakeTokeLifespan = time.Hour
	)
	fakeScopes := []interface{}{"openid", "profile"}
	now := time.Now()
	fakeTime := func() time.Time {
		return now
	}
	var privateKey *rsa.PrivateKey
	type mockParams struct {
		tokenCache         *fake.MockNonNamespacedCacheInterface[*v3.Token]
		tokenClient        *fake.MockNonNamespacedClientInterface[*v3.Token, *v3.TokenList]
		secretCache        *fake.MockCacheInterface[*v1.Secret]
		userLister         *fake.MockNonNamespacedCacheInterface[*v3.User]
		useAttributeLister *fake.MockNonNamespacedCacheInterface[*v3.UserAttribute]
		storage            *mocks.MockStorage
		signingKeyGetter   *mocks.MockSigningKeyGetter
	}

	tests := map[string]struct {
		req                   func() *http.Request
		mockSetup             func(mockParams)
		wantIdTokenClaims     *jwt.MapClaims
		wantAccessTokenClaims *jwt.MapClaims
		wantError             string
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
					Scope:         []string{"openid", "profile"},
					CodeChallenge: oauth2.S256ChallengeFromVerifier(fakeCodeVerifier),
					Nonce:         "",
				}, nil)
				oidcClient := extv1.OIDCClient{
					ObjectMeta: metav1.ObjectMeta{
						Name: fakeClientID,
					},
					Spec: extv1.OIDCClientSpec{
						Secret:       fakeClientSecret,
						TokeLifeSpan: fakeTokeLifespan,
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

				m.userLister.EXPECT().Get(fakeUserID).Return(&v3.User{
					DisplayName: fakeUsername,
					Enabled:     ptr.To(true),
				}, nil)
				m.useAttributeLister.EXPECT().Get(fakeUserID).Return(&v3.UserAttribute{
					GroupPrincipals: map[string]v3.Principals{
						"group": {
							Items: []v3.Principal{
								{
									ObjectMeta: metav1.ObjectMeta{
										Name: fakeGroup,
									},
								},
							},
						},
					},
				}, nil)
				privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
				m.signingKeyGetter.EXPECT().GetSigningKey().Return(privateKey, fakeSigningKey, nil)
			},
			wantIdTokenClaims: &jwt.MapClaims{
				"aud":                []interface{}{fakeClientID},
				"exp":                float64(fakeTime().Add(fakeTokeLifespan).Unix()),
				"iss":                settings.ServerURL.Get() + "/oidc", //TODO
				"iat":                float64(fakeTime().Unix()),
				"preferred_username": fakeUsername,
				"sub":                fakeUserID,
				"auth_provider":      fakeAuthProvider,
				"groups":             []interface{}{fakeGroup},
			},
			wantAccessTokenClaims: &jwt.MapClaims{
				"aud":           []interface{}{fakeClientID},
				"exp":           float64(fakeTime().Add(fakeTokeLifespan).Unix()),
				"iss":           settings.ServerURL.Get() + "/oidc", //TODO
				"iat":           float64(fakeTime().Unix()),
				"sub":           fakeUserID,
				"auth_provider": fakeAuthProvider,
				"scope":         fakeScopes,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := mockParams{
				tokenCache:         fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl),
				tokenClient:        fake.NewMockNonNamespacedClientInterface[*v3.Token, *v3.TokenList](ctrl),
				secretCache:        fake.NewMockCacheInterface[*v1.Secret](ctrl),
				userLister:         fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl),
				useAttributeLister: fake.NewMockNonNamespacedCacheInterface[*v3.UserAttribute](ctrl),
				storage:            mocks.NewMockStorage(ctrl),
				signingKeyGetter:   mocks.NewMockSigningKeyGetter(ctrl),
			}
			if test.mockSetup != nil {
				test.mockSetup(m)
			}
			h := NewHandler(m.tokenCache, m.userLister, m.useAttributeLister, m.storage, m.signingKeyGetter, oidcclients.NewStoreCache(m.secretCache), m.tokenClient)
			h.now = fakeTime
			rec := httptest.NewRecorder()

			h.TokenEndpoint(rec, test.req())

			if test.wantError != "" {
				assert.Equal(t, test.wantError, rec.Body.String())
			}
			var tokenResponse TokenResponse
			err := json.Unmarshal(rec.Body.Bytes(), &tokenResponse)
			assert.NoError(t, err)

			if test.wantIdTokenClaims != nil {
				claims := jwt.MapClaims{}
				_, err := jwt.ParseWithClaims(tokenResponse.IDToken, &claims, func(token *jwt.Token) (interface{}, error) {
					return &privateKey.PublicKey, nil
				})
				assert.NoError(t, err)
				assert.Equal(t, test.wantIdTokenClaims, &claims)
			}
			if test.wantAccessTokenClaims != nil {
				claims := jwt.MapClaims{}
				_, err := jwt.ParseWithClaims(tokenResponse.AccessToken, &claims, func(token *jwt.Token) (interface{}, error) {
					return &privateKey.PublicKey, nil
				})
				assert.NoError(t, err)
				assert.Equal(t, test.wantAccessTokenClaims, &claims)
			}
		})
	}
}
