package oidcprovider

import (
	"context"
	"encoding/json"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	wrangmgmtv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/wrangler"
	corev1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type oidcClientController struct {
	secretClient corev1.SecretClient
	oidcClient   wrangmgmtv3.OIDCClientClient
}

func Register(ctx context.Context, wContext *wrangler.Context) {
	oidcClient := wContext.Mgmt.OIDCClient()
	controller := &oidcClientController{
		secretClient: wContext.Core.Secret(),
		oidcClient:   oidcClient,
	}
	oidcClient.OnChange(ctx, "oidc-client-change", controller.onChange)
}

func (c *oidcClientController) onChange(_ string, oidcClient *v3.OIDCClient) (*v3.OIDCClient, error) {
	if oidcClient == nil {
		return nil, nil
	}

	//TODO check clientID is not changed!
	clientID := "client-id3"
	clientSecret := "client-secret"

	_, err := c.secretClient.Create(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      oidcClient.Name,
			Namespace: "cattle-oidc-clients",
		},
		StringData: map[string]string{
			"client-secret": clientSecret,
		},
	})
	if err != nil && !errors.IsAlreadyExists(err) {
		return nil, err
	}

	patchData := map[string]interface{}{
		"status": map[string]string{
			"clientID": clientID,
		},
	}

	patchBytes, err := json.Marshal(patchData)
	if err != nil {
		return nil, err
	}

	_, err = c.oidcClient.Patch(oidcClient.Name, types.MergePatchType, patchBytes)
	if err != nil {
		return nil, err
	}

	return oidcClient, nil
}
