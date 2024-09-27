package rbac

import (
	"errors"
	"fmt"
	"github.com/rancher/rancher/pkg/controllers/status"
	"reflect"
	"time"

	controllersv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	typesrbacv1 "github.com/rancher/rancher/pkg/generated/norman/rbac.authorization.k8s.io/v1"
	pkgrbac "github.com/rancher/rancher/pkg/rbac"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/util/retry"
)

const (
	clusterRolesExists                       = "ClusterRolesExists"
	clusterRoleBindingsExists                = "ClusterRoleBindingsExists"
	serviceAccountImpersonatorExists         = "ServiceAccountImpersonatorExists"
	crtbLabelsUpdated                        = "CRTBLabelsUpdated"
	roleTemplateDoesNotExist                 = "RoleTemplateDoesNotExist"
	userOrGroupDoesNotExist                  = "UserOrGroupDoesNotExist"
	failedToGetRoleTemplate                  = "FailedToGetRoleTemplate"
	failedToGatherRoles                      = "FailedToGatherRoles"
	failedToCreateRoles                      = "FailedToCreateRoles"
	failedToCreateBindings                   = "FailedToCreateBindings"
	failedToCreateServiceAccountImpersonator = "FailedToCreateServiceAccountImpersonator"
	failedToCreateLabelRequirement           = "FailedToCreateLabelRequirement"
	failedToListCRBs                         = "FailedToListCRBs"
	failedToUpdateCRBs                       = "FailedToUpdateCRBs"
)

func newCRTBLifecycle(m *manager, management *config.ManagementContext) *crtbLifecycle {
	return &crtbLifecycle{
		m:          m,
		rtLister:   management.Management.RoleTemplates("").Controller().Lister(),
		crbLister:  m.workload.RBAC.ClusterRoleBindings("").Controller().Lister(),
		crbClient:  m.workload.RBAC.ClusterRoleBindings(""),
		crtbClient: management.Wrangler.Mgmt.ClusterRoleTemplateBinding(),
	}
}

type crtbLifecycle struct {
	m          managerInterface
	rtLister   v3.RoleTemplateLister
	crbLister  typesrbacv1.ClusterRoleBindingLister
	crbClient  typesrbacv1.ClusterRoleBindingInterface
	crtbClient controllersv3.ClusterRoleTemplateBindingController
}

func (c *crtbLifecycle) Create(obj *v3.ClusterRoleTemplateBinding) (runtime.Object, error) {
	return obj, errors.Join(c.syncCRTB(obj),
		c.setCRTBAsCompleted(obj))
}

func (c *crtbLifecycle) Updated(obj *v3.ClusterRoleTemplateBinding) (runtime.Object, error) {
	return obj, errors.Join(c.reconcileCRTBUserClusterLabels(obj),
		c.syncCRTB(obj),
		c.setCRTBAsCompleted(obj))
}

func (c *crtbLifecycle) Remove(obj *v3.ClusterRoleTemplateBinding) (runtime.Object, error) {
	err := c.ensureCRTBDelete(obj)
	return obj, err
}

func (c *crtbLifecycle) syncCRTB(binding *v3.ClusterRoleTemplateBinding) error {
	condition := metav1.Condition{Type: clusterRolesExists}

	if binding.RoleTemplateName == "" {
		logrus.Warnf("ClusterRoleTemplateBinding %v has no role template set. Skipping.", binding.Name)
		addCondition(binding, condition, roleTemplateDoesNotExist, fmt.Errorf("ClusterRoleTemplateBinding has no role template set"))
		return nil
	}

	if binding.UserName == "" && binding.GroupPrincipalName == "" && binding.GroupName == "" {
		addCondition(binding, condition, userOrGroupDoesNotExist, fmt.Errorf("ClusterRoleTemplateBinding has no UserName, GroupPrincipalName or GroupName set"))
		return nil
	}

	rt, err := c.rtLister.Get("", binding.RoleTemplateName)
	if err != nil {
		addCondition(binding, condition, failedToGetRoleTemplate, fmt.Errorf("couldn't get role template %v: %w", binding.RoleTemplateName, err))
		return err
	}

	roles := map[string]*v3.RoleTemplate{}
	if err := c.m.gatherRoles(rt, roles, 0); err != nil {
		addCondition(binding, condition, failedToGatherRoles, err)
		return err
	}

	if err := c.m.ensureRoles(roles); err != nil {
		addCondition(binding, condition, failedToCreateRoles, err)
		return err
	}
	addCondition(binding, condition, clusterRolesExists, nil)

	condition = metav1.Condition{Type: clusterRoleBindingsExists}
	if err := c.m.ensureClusterBindings(roles, binding); err != nil {
		addCondition(binding, condition, failedToCreateBindings, err)
		return err
	}
	addCondition(binding, condition, clusterRoleBindingsExists, nil)

	condition = metav1.Condition{Type: serviceAccountImpersonatorExists}
	if binding.UserName != "" {
		if err := c.m.ensureServiceAccountImpersonator(binding.UserName); err != nil {
			addCondition(binding, condition, failedToCreateServiceAccountImpersonator, err)
			return err
		}
	}
	addCondition(binding, condition, serviceAccountImpersonatorExists, nil)

	return nil
}

// TODO set conditions!
func (c *crtbLifecycle) ensureCRTBDelete(binding *v3.ClusterRoleTemplateBinding) error {
	set := labels.Set(map[string]string{rtbOwnerLabel: pkgrbac.GetRTBLabel(binding.ObjectMeta)})
	rbs, err := c.crbLister.List("", set.AsSelector())
	if err != nil {
		return fmt.Errorf("couldn't list clusterrolebindings with selector %s: %w", set.AsSelector(), err)
	}

	for _, rb := range rbs {
		if err := c.crbClient.Delete(rb.Name, &metav1.DeleteOptions{}); err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("error deleting clusterrolebinding %v: %w", rb.Name, err)
			}
		}
	}

	if err := c.m.deleteServiceAccountImpersonator(binding.UserName); err != nil {
		return fmt.Errorf("error deleting service account impersonator: %w", err)
	}

	return nil
}

// TODO set conditions!
func (c *crtbLifecycle) reconcileCRTBUserClusterLabels(binding *v3.ClusterRoleTemplateBinding) error {
	/* Prior to 2.5, for every CRTB, following CRBs are created in the user clusters
		1. CRTB.UID is the label value for a CRB, authz.cluster.cattle.io/rtb-owner=CRTB.UID
	Using this labels, list the CRBs and update them to add a label with ns+name of CRTB
	*/
	condition := metav1.Condition{Type: crtbLabelsUpdated}

	if binding.Labels[rtbCrbRbLabelsUpdated] == "true" {
		addCondition(binding, condition, crtbLabelsUpdated, nil)
		return nil
	}

	var returnErr error
	set := labels.Set(map[string]string{rtbOwnerLabelLegacy: string(binding.UID)})
	reqUpdatedLabel, err := labels.NewRequirement(rtbLabelUpdated, selection.DoesNotExist, []string{})
	if err != nil {
		addCondition(binding, condition, failedToCreateLabelRequirement, err)
		return err
	}
	reqNsAndNameLabel, err := labels.NewRequirement(rtbOwnerLabel, selection.DoesNotExist, []string{})
	if err != nil {
		addCondition(binding, condition, failedToCreateLabelRequirement, err)
		return err
	}
	set.AsSelector().Add(*reqUpdatedLabel, *reqNsAndNameLabel)
	userCRBs, err := c.crbClient.List(metav1.ListOptions{LabelSelector: set.AsSelector().Add(*reqUpdatedLabel, *reqNsAndNameLabel).String()})
	if err != nil {
		addCondition(binding, condition, failedToListCRBs, err)
		return err
	}
	bindingValue := pkgrbac.GetRTBLabel(binding.ObjectMeta)
	for _, crb := range userCRBs.Items {
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			crbToUpdate, updateErr := c.crbClient.Get(crb.Name, metav1.GetOptions{})
			if updateErr != nil {
				return updateErr
			}
			if crbToUpdate.Labels == nil {
				crbToUpdate.Labels = make(map[string]string)
			}
			crbToUpdate.Labels[rtbOwnerLabel] = bindingValue
			crbToUpdate.Labels[rtbLabelUpdated] = "true"
			_, err := c.crbClient.Update(crbToUpdate)
			return err
		})
		returnErr = errors.Join(returnErr, retryErr)
	}
	if returnErr != nil {
		addCondition(binding, condition, failedToUpdateCRBs, returnErr)
		return returnErr
	}

	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		crtbToUpdate, updateErr := c.crtbClient.Get(binding.Namespace, binding.Name, metav1.GetOptions{})
		if updateErr != nil {
			return updateErr
		}
		if crtbToUpdate.Labels == nil {
			crtbToUpdate.Labels = make(map[string]string)
		}
		crtbToUpdate.Labels[rtbCrbRbLabelsUpdated] = "true"
		_, err := c.crtbClient.Update(crtbToUpdate)
		return err
	})

	if retryErr != nil {
		addCondition(binding, condition, failedToUpdateCRBs, returnErr)
		return returnErr
	}

	addCondition(binding, condition, crtbLabelsUpdated, nil)

	return nil
}

func (c *crtbLifecycle) setCRTBAsCompleted(crtb *v3.ClusterRoleTemplateBinding) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		crtbFromCluster, err := c.crtbClient.Get(crtb.Namespace, crtb.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if reflect.DeepEqual(crtbFromCluster.Status.RemoteConditions, crtb.Status.RemoteConditions) {
			fmt.Println("REMOTE not updating")
			return nil
		}
		fmt.Println("REMOTE updating!!!!!!!!!!!")

		crtbFromCluster.Status.SummaryRemote = status.SummaryCompleted
		if crtbFromCluster.Status.SummaryLocal == status.SummaryCompleted {
			crtbFromCluster.Status.Summary = status.SummaryCompleted
		}
		for _, c := range crtb.Status.RemoteConditions {
			if c.Status != metav1.ConditionTrue {
				crtbFromCluster.Status.Summary = status.SummaryError
				crtbFromCluster.Status.SummaryRemote = status.SummaryError
				break
			}
		}

		crtbFromCluster.Status.LastUpdateTime = time.Now().String()
		crtbFromCluster.Status.ObservedGenerationRemote = crtb.ObjectMeta.Generation
		crtbFromCluster.Status.RemoteConditions = crtb.Status.RemoteConditions
		crtbFromCluster, err = c.crtbClient.UpdateStatus(crtbFromCluster)
		if err != nil {
			return err
		}
		// For future updates, we want the latest version of our CRTB
		*crtb = *crtbFromCluster
		return nil
	})
}

func addCondition(binding *v3.ClusterRoleTemplateBinding, condition metav1.Condition, reason string, err error) {
	if err != nil {
		condition.Status = metav1.ConditionFalse
		condition.Message = err.Error()
	} else {
		condition.Status = metav1.ConditionTrue
	}
	condition.Reason = reason
	condition.LastTransitionTime = metav1.Time{Time: time.Now()}

	found := false
	for i := range binding.Status.RemoteConditions {
		remoteCondition := &binding.Status.RemoteConditions[i]
		if condition.Type == remoteCondition.Type {
			remoteCondition.Status = condition.Status
			remoteCondition.Reason = condition.Reason
			remoteCondition.Message = condition.Message
			found = true
			fmt.Println("found " + remoteCondition.Type)
		}
	}
	if !found {
		binding.Status.RemoteConditions = append(binding.Status.RemoteConditions, condition)
	}
}
