package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rancher/rancher/pkg/controllers/status"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"time"

	mgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
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
	// RemoteClusterRolesExists indicates that remote CRTB-related ClusterRoles are all created.
	RemoteClusterRolesExists = "RemoteClusterRolesExists"
	// RemoteClusterRoleBindingsExists indicates that remote CRTB-related ClusterRolesBindings are all created.
	RemoteClusterRoleBindingsExists = "RemoteClusterRoleBindingsExists"
	// RemoteServiceAccountImpersonator indicates that ServiceAccount used for impersonation in downstream cluster is created.
	RemoteServiceAccountImpersonator = "RemoteServiceAccountImpersonator"
	/*// RemoteCRTBDeleteOk
	RemoteCRTBDeleteOk = "RemoteCRTBDeleteOk"
	// FailedToDeleteClusterRoleBindings indicates that the controller was unable to delete the CRTB-related cluster role bindings.
	FailedToDeleteClusterRoleBindings = "FailedToDeleteClusterRoleBindings"
	// FailedToDeleteSAImpersonator indicates that the controller was unable to delete the impersonation account for the CRTB's user.
	FailedToDeleteSAImpersonator = "FailedToDeleteSAImpersonator"
	// FailedToEnsureClusterRoleBindings indicates that the controller was unable to create the cluster roles for the role template referenced by the CRTB.
	FailedToEnsureClusterRoleBindings = "FailedToEnsureClusterRoleBindings"
	// FailedToEnsureRoles indicates that the controller was unable to create the roles for the role template referenced by the CRTB.
	FailedToEnsureRoles = "FailedToEnsureRoles"
	// FailedToEnsureSAImpersonator means that the controller was unable to create the impersonation account for the CRTB's user.
	FailedToEnsureSAImpersonator = "FailedToEnsureSAImpersonator"
	// RemoteFailedToGetClusterRoleBindings means that the remote controller was unable to retrieve the CRTB-related cluster role bindings to update.
	RemoteFailedToGetClusterRoleBindings = "RemoteFailedToGetClusterRoleBindings"
	// RemoteFailedToGetLabelRequirements indicates remote issues with the CRTB meta data preventing creation of label requirements.
	RemoteFailedToGetLabelRequirements = "RemoteFailedToGetLabelRequirements"
	// FailedToGetRoleTemplate means that the controller failed to locate the role template referenced by the CRTB.
	FailedToGetRoleTemplate = "FailedToGetRoleTemplate"
	// FailedToGetRoles indicates that the controller failed to locate the roles for the role template referenced by the CRTB.
	FailedToGetRoles = "FailedToGetRoles"
	// RemoteFailedToUpdateCRTBLabels means the remote controller failed to update the CRTB labels indicating success of CRB/RB label updates.
	RemoteFailedToUpdateCRTBLabels = "RemoteFailedToUpdateCRTBLabels"
	// RemoteFailedToUpdateClusterRoleBindings means that the remote controller was unable to properly update the CRTB-related cluster role bindings.
	RemoteFailedToUpdateClusterRoleBindings = "RemoteFailedToUpdateClusterRoleBindings"
	// RemoteLabelsSet is a success indicator. The remote CRTB-related labels are all set.
	RemoteLabelsSet = "RemoteLabelsSet"*/
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
	if err := c.setCRTBAsInProgress(obj); err != nil {
		return obj, err
	}
	if err := c.syncCRTB(obj); err != nil {
		return obj, err
	}

	return obj, c.setCRTBAsCompleted(obj)
}

func (c *crtbLifecycle) Updated(obj *v3.ClusterRoleTemplateBinding) (runtime.Object, error) {
	if err := c.reconcileCRTBUserClusterLabels(obj); err != nil {
		return obj, err
	}
	err := c.syncCRTB(obj)
	return obj, err
}

func (c *crtbLifecycle) Remove(obj *v3.ClusterRoleTemplateBinding) (runtime.Object, error) {
	err := c.ensureCRTBDelete(obj)
	return obj, err
}

func (c *crtbLifecycle) syncCRTB(binding *v3.ClusterRoleTemplateBinding) error {
	condition := metav1.Condition{Type: RemoteClusterRolesExists}

	if binding.RoleTemplateName == "" {
		logrus.Warnf("ClusterRoleTemplateBinding %v has no role template set. Skipping.", binding.Name)
		return addCondition(c.crtbClient, binding, condition, RemoteClusterRolesExists, binding.Name, fmt.Errorf("ClusterRoleTemplateBinding has no role template set"))
	}

	if binding.UserName == "" && binding.GroupPrincipalName == "" && binding.GroupName == "" {
		return addCondition(c.crtbClient, binding, condition, RemoteClusterRolesExists, binding.Name, fmt.Errorf("ClusterRoleTemplateBinding has no UserName, GroupPrincipalName or GroupName set"))
	}

	rt, err := c.rtLister.Get("", binding.RoleTemplateName)
	if err != nil {
		return addCondition(c.crtbClient, binding, condition, RemoteClusterRolesExists, binding.Name, fmt.Errorf("couldn't get role template %v: %w", binding.RoleTemplateName, err))
	}

	roles := map[string]*v3.RoleTemplate{}
	if err := c.m.gatherRoles(rt, roles, 0); err != nil {
		return addCondition(c.crtbClient, binding, condition, RemoteClusterRolesExists, binding.Name, fmt.Errorf("couldn't gather roles: %w", err))
	}

	if err := c.m.ensureRoles(roles); err != nil {
		return addCondition(c.crtbClient, binding, condition, RemoteClusterRolesExists, binding.Name, fmt.Errorf("couldn't ensure roles: %w", err))
	}
	if err = addCondition(c.crtbClient, binding, condition, RemoteClusterRolesExists, binding.Name, nil); err != nil {
		return fmt.Errorf("couldn't add condition RemoteClusterRolesExists: %w", err)
	}

	if err := c.m.ensureClusterBindings(roles, binding); err != nil {
		return addCondition(c.crtbClient, binding, condition, RemoteClusterRoleBindingsExists, binding.Name, fmt.Errorf("couldn't cluster bindings: %w", err))
	}
	if err = addCondition(c.crtbClient, binding, condition, RemoteClusterRoleBindingsExists, binding.Name, nil); err != nil {
		return fmt.Errorf("couldn't add condition RemoteClusterRoleBindingsExists: %w", err)
	}

	if binding.UserName != "" {
		if err := c.m.ensureServiceAccountImpersonator(binding.UserName); err != nil {
			return addCondition(c.crtbClient, binding, condition, RemoteServiceAccountImpersonator, binding.Name, fmt.Errorf("couldn't ensure service account impersonator: %w", err))
		}
	}
	return addCondition(c.crtbClient, binding, condition, RemoteServiceAccountImpersonator, binding.Name, nil)
}

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

func (c *crtbLifecycle) reconcileCRTBUserClusterLabels(binding *v3.ClusterRoleTemplateBinding) error {
	/* Prior to 2.5, for every CRTB, following CRBs are created in the user clusters
		1. CRTB.UID is the label value for a CRB, authz.cluster.cattle.io/rtb-owner=CRTB.UID
	Using this labels, list the CRBs and update them to add a label with ns+name of CRTB
	*/
	if binding.Labels[rtbCrbRbLabelsUpdated] == "true" {
		return nil
	}

	var returnErr error
	set := labels.Set(map[string]string{rtbOwnerLabelLegacy: string(binding.UID)})
	reqUpdatedLabel, err := labels.NewRequirement(rtbLabelUpdated, selection.DoesNotExist, []string{})
	if err != nil {
		return err
	}
	reqNsAndNameLabel, err := labels.NewRequirement(rtbOwnerLabel, selection.DoesNotExist, []string{})
	if err != nil {
		return err
	}
	set.AsSelector().Add(*reqUpdatedLabel, *reqNsAndNameLabel)
	userCRBs, err := c.crbClient.List(metav1.ListOptions{LabelSelector: set.AsSelector().Add(*reqUpdatedLabel, *reqNsAndNameLabel).String()})
	if err != nil {
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
	return retryErr
}

func (c *crtbLifecycle) setCRTBAsInProgress(binding *v3.ClusterRoleTemplateBinding) error {
	// Keep information managed by the local controller.
	// Wipe only information managed here
	//binding.Status.Conditions = status.RemoveConditions(binding.Status.Conditions, crtb.RemoteConditions)

	// TODO clear conditions just for rbac not auth!
	binding.Status.Conditions = []metav1.Condition{}

	binding.Status.Summary = status.SummaryInProgress
	binding.Status.LastUpdateTime = time.Now().String()
	updatedCRTB, err := c.crtbClient.UpdateStatus(binding)
	if err != nil {
		return err
	}
	// For future updates, we want the latest version of our CRTB
	*binding = *updatedCRTB
	return nil
}

func (c *crtbLifecycle) setCRTBAsCompleted(binding *v3.ClusterRoleTemplateBinding) error {
	// set summary based on error conditions
	failed := false
	for _, c := range binding.Status.Conditions {
		if c.Status != metav1.ConditionTrue {
			binding.Status.Summary = status.SummaryError
			failed = true
			break
		}
	}

	if !failed {
		binding.Status.Summary = status.SummaryCompleted
	}
	// no error conditions. check for all (local and remote!) success conditions
	// note: keep the status as in progress if only partial sucess was found
	/* TODO!
	   if !failed && status.HasAllOf(binding.Status.Conditions, crtb.Successes) {
	   		binding.Status.Summary = status.SummaryCompleted
	   	}

	   	logrus.Infof("ZZZ REMOTE COM %s/%s (%v), ((%v))", binding.ObjectMeta.Namespace, binding.ObjectMeta.Name,
	   		binding.Status.Summary, binding.Status.Conditions)
	*/
	binding.Status.LastUpdateTime = time.Now().String()
	binding.Status.ObservedGeneration = binding.ObjectMeta.Generation
	updatedCRTB, err := c.crtbClient.UpdateStatus(binding)
	if err != nil {
		return err
	}
	// For future updates, we want the latest version of our CRTB
	*binding = *updatedCRTB
	return nil
}

func addCondition(crtbClient controllersv3.ClusterRoleTemplateBindingController, binding *v3.ClusterRoleTemplateBinding, condition metav1.Condition, reason, name string, err error) error {
	/*
		patchBytes, unchanged, err := preparePatchBytesForPodStatus(namespace, name, uid, oldPodStatus, newPodStatus)
			if err != nil {
				return nil, nil, false, err
			}
			if unchanged {
				return nil, patchBytes, true, nil
			}

			updatedPod, err := c.CoreV1().Pods(namespace).Patch(ctx, name, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{}, "status")
			if err != nil {
				return nil, nil, false, fmt.Errorf("failed to patch status %q for pod %q/%q: %v", patchBytes, namespace, name, err)
			}
			return updatedPod, patchBytes, false, nil
	*/
	oldStatus := binding.Status.DeepCopy()
	if err != nil {
		condition.Status = metav1.ConditionFalse
		condition.Message = fmt.Sprintf("%s not created: %v", name, err)
	} else {
		condition.Status = metav1.ConditionTrue
		condition.Message = fmt.Sprintf("%s created", name)
	}
	condition.Reason = reason
	condition.LastTransitionTime = metav1.Time{Time: time.Now()}
	binding.Status.Conditions = append(binding.Status.Conditions, condition)

	patchBytes, changed, err := preparePatchBytesForCRTBStatus(binding.Name, binding.UID, *oldStatus, binding.Status)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}

	_, err = crtbClient.Patch(binding.Namespace, binding.Name, types.StrategicMergePatchType, patchBytes)
	if err != nil {
		return fmt.Errorf("failed to patch CRTB status condition: %v", err)
	}

	return nil
}

func preparePatchBytesForCRTBStatus(name string, uid types.UID, oldStatus, newStatus mgmtv3.ClusterRoleTemplateBindingStatus) ([]byte, bool, error) {
	oldData, err := json.Marshal(mgmtv3.ClusterRoleTemplateBinding{
		Status: oldStatus,
	})
	if err != nil {
		return nil, false, fmt.Errorf("failed to Marshal oldData for crtb %q: %v", name, err)
	}

	newData, err := json.Marshal(mgmtv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{UID: uid}, // only put the uid in the new object to ensure it appears in the patch as a precondition
		Status:     newStatus,
	})
	if err != nil {
		return nil, false, fmt.Errorf("failed to Marshal newData for ctrb %q: %v", name, err)
	}

	patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldData, newData, mgmtv3.ClusterRoleTemplateBinding{})
	if err != nil {
		return nil, false, fmt.Errorf("failed to CreateTwoWayMergePatch for crtb %q: %v", name, err)
	}
	return patchBytes, bytes.Equal(patchBytes, []byte(fmt.Sprintf(`{"metadata":{"uid":%q}}`, uid))), nil
}
