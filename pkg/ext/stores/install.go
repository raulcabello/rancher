package stores

import (
	"fmt"
	extv1 "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	"github.com/rancher/rancher/pkg/ext/oidcclients"
	"github.com/rancher/rancher/pkg/wrangler"
	steveext "github.com/rancher/steve/pkg/ext"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
)

func InstallStores(server *steveext.ExtensionAPIServer, wranglerContext *wrangler.Context, scheme *runtime.Scheme) error {
	steveext.AddToScheme(scheme)

	// To add a store to the extensionAPIServer, simply add the types to the *runtime.Scheme and
	// call InstallStore [steveext.ExtensionAPIServer.Install].
	//
	// Here's an example:
	//
	extv1.AddToScheme(scheme)
	//
	//      authorizer := server.GetAuthorizer()
	//	store := newMapStore(authorizer)
	//
	//      err := server.Install("testtypes", extv1.SchemeGroupVersion.WithKind("TestType"), store)
	//	if err != nil {
	//		return fmt.Errorf("unable to install mapStore: %w", err)
	//	}

	store := oidcclients.New(wranglerContext.Core.Secret(), wranglerContext.Core.Secret().Cache(), wranglerContext.Core.Namespace())
	err := server.Install(
		oidcclients.PluralName,
		extv1.SchemeGroupVersion.WithKind(oidcclients.Kind),
		store)
	if err != nil {
		return fmt.Errorf("unable to install %s store: %w", oidcclients.Kind, err)
	}
	logrus.Infof("Successfully installed ext token store")

	return nil
}
