package oidcprovider

import (
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestOnChange(t *testing.T) {
	ctlr := gomock.NewController(t)
	type mockParams struct {
		secretCache     *fake.MockCacheInterface[*v1.Secret]
		secretClient    *fake.MockClientInterface[*v1.Secret, *v1.SecretList]
		oidcClientCache *fake.MockNonNamespacedCacheInterface[*v3.OIDCClient]
		oidcClient      *fake.MockNonNamespacedClientInterface[*v3.OIDCClient, *v3.OIDCClientList]
	}

	tests := map[string]struct {
		oidcClient         *v3.OIDCClient
		setupMock          func(*mockParams)
		expectedErr        string
		expectedOidcClient *v3.OIDCClient
	}{
		"clientID and clientSecret is created": {
			oidcClient: &v3.OIDCClient{
				ObjectMeta: metav1.ObjectMeta{},
			},
			setupMock: func(p *mockParams) {

			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mocks := &mockParams{
				secretCache:     fake.NewMockCacheInterface[*v1.Secret](ctlr),
				secretClient:    fake.NewMockClientInterface[*v1.Secret, *v1.SecretList](ctlr),
				oidcClientCache: fake.NewMockNonNamespacedCacheInterface[*v3.OIDCClient](ctlr),
				oidcClient:      fake.NewMockNonNamespacedClientInterface[*v3.OIDCClient, *v3.OIDCClientList](ctlr),
			}
			if test.setupMock != nil {
				test.setupMock(mocks)
			}

			c := oidcClientController{
				secretClient:    mocks.secretClient,
				secretCache:     mocks.secretCache,
				oidcClient:      mocks.oidcClient,
				oidcClientCache: mocks.oidcClientCache,
			}

			oidcClient, err := c.onChange("", test.oidcClient)

			if test.expectedErr != "" {
				assert.ErrorContains(t, err, test.expectedErr)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, test.expectedOidcClient, oidcClient)
		})
	}
}
