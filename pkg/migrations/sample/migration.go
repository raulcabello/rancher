package sample

import (
	"context"
	"errors"
	"fmt"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/rancher/rancher/pkg/migrations"
	"github.com/rancher/rancher/pkg/migrations/changes"
)

const userSecretsNamespace = "cattle-local-users-password"

func init() {
	migrations.Register(userMigration{})
}

type userMigration struct {
}

// Name implements the Migration interface.
func (u userMigration) Name() string {
	return "user-migration"
}

// Changes implements the Migration interface.
//
// This migration finds current Users with password. For each user:
// - Copy the password to the cattle-user-password namespace
// - Remove password from User
func (u userMigration) Changes(ctx context.Context, client changes.Interface, opts migrations.MigrationOptions) (*migrations.MigrationChanges, error) {
	users, err := client.Resource(schema.GroupVersionResource{
		Resource: "users",
		Group:    "management.cattle.io",
		Version:  "v3",
	}).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing users to calculate migration: %s", err)
	}

	var changeSets []migrations.ChangeSet
	var migrationErr error
	for _, uns := range users.Items {
		var user v3.User
		err := runtime.DefaultUnstructuredConverter.FromUnstructured(uns.UnstructuredContent(), &user)
		if err != nil {
			// TODO: improve this error
			migrationErr = errors.Join(migrationErr, err)
			continue
		}

		if user.Password != "" {
			secret := &v1.Secret{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      user.Name,
					Namespace: userSecretsNamespace,
					// TODO add owner ref
				},
				StringData: map[string]string{
					"password": user.Password,
				},
			}
			raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(secret)
			if err != nil {
				// TODO: improve this error
				migrationErr = errors.Join(migrationErr, err)
				continue
			}

			unsSecret := &unstructured.Unstructured{Object: raw}
			changeSets = append(changeSets, migrations.ChangeSet{
				changes.ResourceChange{
					Operation: changes.OperationCreate,
					Create:    &changes.CreateChange{Resource: unsSecret},
				},
				changes.ResourceChange{
					Operation: changes.OperationPatch,
					Patch: &changes.PatchChange{
						ResourceRef: changes.ResourceReference{
							ObjectRef: types.NamespacedName{
								Name: user.Name,
							},
							Group:    "management.cattle.io",
							Resource: "users",
							Version:  "v3",
						},
						Operations: []changes.PatchOperation{
							{
								Operation: "remove",
								Path:      "/password",
							},
						},
						Type: changes.PatchApplicationJSON,
					},
				},
			},
			)
		}
	}

	if migrationErr != nil {
		return nil, migrationErr
	}

	return &migrations.MigrationChanges{Changes: changeSets}, nil
}
