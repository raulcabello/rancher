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
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"os"
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
	kubeCfg           string //TODO try to not use it
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

	kubeCfg = createKubeconfigFileForRestConfig(restCfg)
	bytes, err := os.ReadFile(kubeCfg)
	Expect(err).NotTo(HaveOccurred())

	clientCfg, err := clientcmd.NewClientConfigFromBytes(bytes)
	Expect(err).NotTo(HaveOccurred())

	wranglerContext, err := wrangler.NewContext(ctx, clientCfg, restCfg)
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
	Expect(os.Remove(kubeCfg)).ToNot(HaveOccurred())
	Expect(testEnv.Stop()).ToNot(HaveOccurred())
})

func createKubeconfigFileForRestConfig(restConfig *rest.Config) string {
	clusters := make(map[string]*clientcmdapi.Cluster)
	clusters["default-cluster"] = &clientcmdapi.Cluster{
		Server:                   restConfig.Host,
		CertificateAuthorityData: restConfig.CAData,
	}
	contexts := make(map[string]*clientcmdapi.Context)
	contexts["default-context"] = &clientcmdapi.Context{
		Cluster:  "default-cluster",
		AuthInfo: "default-user",
	}
	authinfos := make(map[string]*clientcmdapi.AuthInfo)
	authinfos["default-user"] = &clientcmdapi.AuthInfo{
		ClientCertificateData: restConfig.CertData,
		ClientKeyData:         restConfig.KeyData,
	}
	clientConfig := clientcmdapi.Config{
		Kind:           "Config",
		APIVersion:     "v1",
		Clusters:       clusters,
		Contexts:       contexts,
		CurrentContext: "default-context",
		AuthInfos:      authinfos,
	}
	kubeConfigFile, _ := os.CreateTemp("", "kubeconfig") //TODO remove?
	_ = clientcmd.WriteToFile(clientConfig, kubeConfigFile.Name())
	return kubeConfigFile.Name()
}
