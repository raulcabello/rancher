package globalrole

import (
	"context"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/controllers/management/auth/globalroles"
	"github.com/rancher/rancher/pkg/multiclustermanager"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/rancher/rancher/pkg/wrangler"
	"github.com/rancher/wrangler/v2/pkg/crd"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"path/filepath"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	cancel            context.CancelFunc
	ctx               context.Context
	testEnv           *envtest.Environment
	managementContext *config.ManagementContext
)

const (
	timeout = 30 * time.Second
)

func TestFleet(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "GlobalRole Bundle Suite")
}

var _ = BeforeSuite(func() {
	SetDefaultEventuallyTimeout(timeout)
	ctx, cancel = context.WithCancel(context.TODO())
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "..", "pkg", "crds", "yaml", "generated", "management.cattle.io_globalroles.yaml"),
			filepath.Join("..", "..", "..", "pkg", "crds", "yaml", "generated", "management.cattle.io_globalrolebindings.yaml"),
		},
		ErrorIfCRDPathMissing: true,
	}

	restCfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(restCfg).NotTo(BeNil())

	registerCRDs(restCfg)

	wranglerContext, err := wrangler.NewContext(ctx, nil, restCfg)
	scaledContext, clusterManager, _, err := multiclustermanager.BuildScaledContext(ctx, wranglerContext, &multiclustermanager.Options{})
	Expect(err).NotTo(HaveOccurred())

	managementContext, err = scaledContext.NewManagementContext()
	Expect(err).NotTo(HaveOccurred())

	globalroles.Register(ctx, managementContext, clusterManager)
	startControllers(managementContext)
	startCache()
})

func startControllers(managementContext *config.ManagementContext) {
	grc, err := managementContext.ControllerFactory.ForKind(schema.GroupVersionKind{
		Group:   "management.cattle.io",
		Version: "v3",
		Kind:    "GlobalRoleBinding",
	})
	Expect(err).NotTo(HaveOccurred())

	grbc, err := managementContext.ControllerFactory.ForKind(schema.GroupVersionKind{
		Group:   "management.cattle.io",
		Version: "v3",
		Kind:    "GlobalRole",
	})
	Expect(err).NotTo(HaveOccurred())

	Expect(grc.Start(ctx, 1)).NotTo(HaveOccurred())
	Expect(grbc.Start(ctx, 1)).NotTo(HaveOccurred())
}

func registerCRDs(cfg *rest.Config) {
	factory, err := crd.NewFactoryFromClient(cfg)
	Expect(err).NotTo(HaveOccurred())
	Expect(factory.BatchCreateCRDs(ctx, crd.CRD{
		SchemaObject: v3.FleetWorkspace{},
		NonNamespace: true,
	}).BatchWait()).NotTo(HaveOccurred())
}

func startCache() {
	Expect(managementContext.Wrangler.ControllerFactory.SharedCacheFactory().StartGVK(ctx, schema.GroupVersionKind{
		Group:   "rbac.authorization.k8s.io",
		Version: "v1",
		Kind:    "ClusterRole",
	})).NotTo(HaveOccurred())
	Expect(managementContext.Wrangler.ControllerFactory.SharedCacheFactory().StartGVK(ctx, schema.GroupVersionKind{
		Group:   "rbac.authorization.k8s.io",
		Version: "v1",
		Kind:    "ClusterRoleBinding",
	})).NotTo(HaveOccurred())
	Expect(managementContext.Wrangler.ControllerFactory.SharedCacheFactory().StartGVK(ctx, schema.GroupVersionKind{
		Group:   "rbac.authorization.k8s.io",
		Version: "v1",
		Kind:    "Role",
	})).NotTo(HaveOccurred())
	Expect(managementContext.Wrangler.ControllerFactory.SharedCacheFactory().StartGVK(ctx, schema.GroupVersionKind{
		Group:   "rbac.authorization.k8s.io",
		Version: "v1",
		Kind:    "RoleBinding",
	})).NotTo(HaveOccurred())
}

var _ = AfterSuite(func() {
	cancel()
	Expect(testEnv.Stop()).ToNot(HaveOccurred())
})
