package requests

import (
	"context"
	"errors"
	"github.com/gorilla/mux"
	authcontext "github.com/rancher/rancher/pkg/auth/context"
	"github.com/rancher/rancher/pkg/types/config"
	v1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"net/http"
	"strings"

	"github.com/rancher/rancher/pkg/auth/audit"
	"github.com/rancher/rancher/pkg/auth/requests/sar"
	"github.com/rancher/steve/pkg/auth"
	"k8s.io/apimachinery/pkg/util/sets"
	k8sUser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
)

type impersonatingAuth struct {
	sar           sar.SubjectAccessReview
	scaledContext *config.ScaledContext
}

func NewImpersonatingAuth(sar sar.SubjectAccessReview, scaledContext *config.ScaledContext) auth.Authenticator {
	return &impersonatingAuth{
		sar:           sar,
		scaledContext: scaledContext, //TODO just cluster k8sClient?
	}
}

func (h *impersonatingAuth) Authenticate(req *http.Request) (k8sUser.Info, bool, error) {
	userInfo, authed := request.UserFrom(req.Context())
	if !authed {
		return nil, false, nil
	}
	user := userInfo.GetName()
	groups := userInfo.GetGroups()

	var impersonateUser bool
	var impersonateGroup bool

	reqUser := req.Header.Get("Impersonate-User")
	var reqGroup []string
	if g, ok := req.Header["Impersonate-Group"]; ok {
		reqGroup = g
	}

	auditUser, ok := audit.FromContext(req.Context())
	if ok {
		auditUser.RequestUser = reqUser
		auditUser.RequestGroups = reqGroup
	}

	// If there is an impersonate header, the incoming request is attempting to
	// impersonate a different user, verify the token user is authz to impersonate
	if h.sar != nil {
		if reqUser != "" && reqUser != user {
			canDo, err := h.sar.UserCanImpersonateUser(req, user, reqUser)
			if err != nil {
				return nil, false, err
			} else if !canDo {
				return nil, false, errors.New("not allowed to impersonate")
			}
			impersonateUser = true
		}

		if len(reqGroup) > 0 && !groupsEqual(reqGroup, groups) {
			canDo, err := h.sar.UserCanImpersonateGroups(req, user, reqGroup)
			if err != nil {
				return nil, false, err
			} else if !canDo {
				return nil, false, errors.New("not allowed to impersonate")
			}
			impersonateGroup = true
		}
	}

	var extra map[string][]string
	if impersonateUser || impersonateGroup {
		if impersonateUser {
			user = reqUser
		}
		if impersonateGroup {
			groups = reqGroup
		} else {
			groups = nil
		}
		groups = append(groups, k8sUser.AllAuthenticated)
		for k, v := range req.Header {
			if strings.HasPrefix(k, "Impersonate-Extra-") {
				extra[k] = v
			}
		}

		if strings.HasPrefix(user, serviceaccount.ServiceAccountUsernamePrefix) {
			treq := &v1.TokenRequest{
				Spec: v1.TokenRequestSpec{
					Audiences: []string{},
				},
			}
			clusterID := mux.Vars(req)["clusterID"]
			if clusterID == "" {
				return nil, false, errors.New("clusterID not found")
			}
			k8sClient, err := h.scaledContext.Wrangler.MultiClusterManager.K8sClient(clusterID)
			token, err := k8sClient.CoreV1().ServiceAccounts("test").CreateToken(context.Background(), "issue", treq, metav1.CreateOptions{})
			if err != nil {
				return nil, false, err
			}
			req.Header.Set("Authorization", "Bearer "+token.Status.Token)
			req.Header.Del("Impersonate-User")
			//	req.Header.Del("Impersonate-Group") TODO check impersonating group
			*req = *req.WithContext(authcontext.SetSAAuthenticated(req.Context()))
		}
	} else {
		extra = userInfo.GetExtra()
	}

	return &k8sUser.DefaultInfo{
		Name:   user,
		UID:    user,
		Groups: groups,
		Extra:  extra,
	}, true, nil
}

func groupsEqual(group1, group2 []string) bool {
	if len(group1) != len(group2) {
		return false
	}

	return sets.NewString(group1...).Equal(sets.NewString(group2...))
}
