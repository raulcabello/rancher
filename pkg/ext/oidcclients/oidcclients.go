package oidcclients

import (
	"context"
	"encoding/json"
	"fmt"
	extv1 "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	extcore "github.com/rancher/steve/pkg/ext"
	v1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
)

const (
	PluralName = "oidcclients"
	Kind       = "OIDCClient"
	namespace  = "cattle-oidc-clients"
	secretKey  = "oidc-client"
)

var GV = schema.GroupVersion{
	Group:   "ext.cattle.io",
	Version: "v1",
}

var GVK = schema.GroupVersionKind{
	Group:   GV.Group,
	Version: GV.Version,
	Kind:    Kind,
}
var GVR = schema.GroupVersionResource{
	Group:    GV.Group,
	Version:  GV.Version,
	Resource: PluralName,
}

type Store struct {
	secretClient    v1.SecretClient
	secretCache     v1.SecretCache
	namespaceClient v1.NamespaceClient
	initialized     bool
}

func New(secretClient v1.SecretController, secretCache v1.SecretCache, namespaceClient v1.NamespaceClient) *Store {
	return &Store{
		secretClient:    secretClient,
		secretCache:     secretCache,
		namespaceClient: namespaceClient,
	}
}

// New implements [rest.Storage]
func (s *Store) New() runtime.Object {
	obj := &extv1.OIDCClient{}
	obj.GetObjectKind().SetGroupVersionKind(GVK)
	return obj
}

// Destroy implements [rest.Storage]
func (s *Store) Destroy() {
}

// NamespaceScoped implements [rest.Scoper]
func (s *Store) NamespaceScoped() bool {
	return false
}

// GroupVersionKind implements [rest.GroupVersionKindProvider]
func (s *Store) GroupVersionKind(_ schema.GroupVersion) schema.GroupVersionKind {
	return GVK
}

// GetSingularName implements [rest.SingularNameProvider]
func (s *Store) GetSingularName() string {
	return "oidcclient"
}

// Create implements [rest.Creator]
func (s *Store) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	if !s.initialized {
		_, err := s.namespaceClient.Create(&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespace,
			},
		})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
		s.initialized = true
	}

	if createValidation != nil {
		err := createValidation(ctx, obj)
		if err != nil {
			return obj, err
		}
	}

	dryRun := options != nil && len(options.DryRun) > 0 && options.DryRun[0] == metav1.DryRunAll
	if dryRun {
		return obj, nil
	}

	oidcClient, ok := obj.(*extv1.OIDCClient)
	if !ok {
		var o *extv1.OIDCClient
		return nil, apierrors.NewInternalError(fmt.Errorf("expected %T but got %T",
			o, obj))
	}

	json, err := json.Marshal(oidcClient)
	if err != nil {
		return nil, err
	}
	// TODO validation
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      oidcClient.Name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			secretKey: json,
		},
	}

	_, err = s.secretClient.Create(&secret)
	if err != nil {
		return nil, err
	}

	return oidcClient, nil
}

func (s *Store) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	secret, err := s.secretClient.Get(namespace, name, *options)
	if err != nil {
		return nil, err
	}

	var oidcClient *extv1.OIDCClient

	err = json.Unmarshal(secret.Data[secretKey], &oidcClient)
	if err != nil {
		return nil, err
	}

	return oidcClient, nil
}

func (s *Store) List(ctx context.Context, internaloptions *metainternalversion.ListOptions) (runtime.Object, error) {
	options, err := extcore.ConvertListOptions(internaloptions)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	secrets, err := s.secretClient.List(namespace, *options)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	oidcClientList := extv1.OIDCClientList{
		ListMeta: metav1.ListMeta{
			ResourceVersion: secrets.ResourceVersion,
		},
	}
	for _, secret := range secrets.Items {
		var oidcClient *extv1.OIDCClient
		err = json.Unmarshal(secret.Data["oidcClient"], &oidcClient)
		if err != nil {
			return nil, apierrors.NewInternalError(err)
		}
		oidcClientList.Items = append(oidcClientList.Items, *oidcClient)
	}

	return &oidcClientList, nil
}

// NewList implements [rest.Lister]
func (s *Store) NewList() runtime.Object {
	objList := &extv1.OIDCClientList{}
	objList.GetObjectKind().SetGroupVersionKind(GVK)
	return objList
}

// ConvertToTable implements [rest.Lister]
func (s *Store) ConvertToTable(
	ctx context.Context,
	object runtime.Object,
	tableOptions runtime.Object) (*metav1.Table, error) {

	return extcore.ConvertToTableDefault[*extv1.OIDCClient](ctx, object, tableOptions,
		GVR.GroupResource())
}

func (s *Store) GetFromCache(name string) (*extv1.OIDCClient, error) {
	secret, err := s.secretCache.Get(namespace, name)
	if err != nil {
		return nil, err
	}

	var oidcClient *extv1.OIDCClient
	err = json.Unmarshal(secret.Data[secretKey], &oidcClient)
	if err != nil {
		return nil, err
	}

	return oidcClient, nil
}

func (s *Store) ListFromCache() (runtime.Object, error) {
	secrets, err := s.secretCache.List(namespace, labels.Everything())
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	oidcClientList := extv1.OIDCClientList{}
	for _, secret := range secrets {
		var oidcClient *extv1.OIDCClient
		err = json.Unmarshal(secret.Data["oidcClient"], &oidcClient)
		if err != nil {
			return nil, apierrors.NewInternalError(err)
		}
		oidcClientList.Items = append(oidcClientList.Items, *oidcClient)
	}

	return &oidcClientList, nil
}

//TODO update
