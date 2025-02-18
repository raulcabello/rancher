package token

import (
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	wrangmgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/oidc/session"
	corecontrollers "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenEndpoint(t *testing.T) {
	ctrl := gomock.NewController(t)
	type mocks struct {
		tokenCache         wrangmgmtv3.TokenCache
		secretCache        corecontrollers.SecretCache
		userLister         wrangmgmtv3.UserCache
		useAttributeLister wrangmgmtv3.UserAttributeCache
		storage            session.Storage
	}

	tests := map[string]struct {
		req          func() *http.Request
		mockSetup    func(mocks)
		jwks         func() signingKeyGetter
		wantRedirect string
		wantHttpCode int
		wantError    string
	}{}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := mocks{
				tokenCache:         fake.NewMockNonNamespacedCacheInterface[*v3.Token](ctrl),
				secretCache:        fake.NewMockCacheInterface[*v1.Secret](ctrl),
				userLister:         fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl),
				useAttributeLister: fake.NewMockNonNamespacedCacheInterface[*v3.UserAttribute](ctrl),
				storage:            nil,
			}
			h := NewHandler(m.tokenCache, m.userLister, m.useAttributeLister, m.storage, test.jwks())

			rec := httptest.NewRecorder()

			h.TokenEndpoint(rec, test.req())

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
