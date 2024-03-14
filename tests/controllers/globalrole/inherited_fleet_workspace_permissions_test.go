package globalrole

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Fleet workspace permissions", func() {

	When("GlobalRole contains Fleet workspace rules", func() {
		var (
			gr  *v3.GlobalRole
			grb *v3.GlobalRoleBinding
		)

		BeforeEach(func() {
			gr = &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fleet-gr",
				},
				InheritedFleetWorkspacePermissions: v3.FleetWorkspacePermission{
					ResourceRules: []v1.PolicyRule{
						{
							Verbs:     []string{"get"},
							APIGroups: []string{"fleet.cattle.io"},
							Resources: []string{"gitrepos"},
						},
					},
					WorkspaceVerbs: []string{"get", "list"},
				},
			}
			grb = &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "grb",
				},
				GlobalRoleName: gr.Name,
				UserName:       "test", //TODO create user?
			}
		})

		JustBeforeEach(func() {
			_, err := managementContext.Management.GlobalRoles("").Create(gr)
			Expect(err).ToNot(HaveOccurred())
			_, err = managementContext.Management.GlobalRoleBindings("").Create(grb)
			Expect(err).ToNot(HaveOccurred())

			_, err = managementContext.Management.FleetWorkspaces("").Create(&v3.FleetWorkspace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
			})
			Expect(err).ToNot(HaveOccurred())

		})

		AfterEach(func() {
			Expect(managementContext.Management.GlobalRoles("").Delete(gr.Name, nil)).ToNot(HaveOccurred())
			Expect(managementContext.Management.GlobalRoleBindings("").Delete(grb.Name, nil)).ToNot(HaveOccurred())
		})

		It("ClusterRole is created", func() {
			var (
				cr  *v1.ClusterRole
				err error
			)
			Eventually(func() error {
				cr, err = managementContext.RBAC.ClusterRoles("").Get("fwcr-"+gr.Name, metav1.GetOptions{})
				return err
			}).ShouldNot(HaveOccurred())

			Expect(cr.Rules).ToNot(BeNil())
		})
	})
})
