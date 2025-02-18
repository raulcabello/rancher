// +kubebuilder:skip
package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// OIDCClient represents an application that uses Rancher OIDC provider as its authentication provider.
type OIDCClient struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec OIDCClientSpec `json:"spec"`
}

type OIDCClientSpec struct {
	Secret               string      `json:"secret"`
	RedirectURIs         []string    `json:"redirectURIs"`
	TokeLifeSpan         metav1.Time `json:"tokeLifeSpan"`
	RefreshTokenLifeSpan metav1.Time `json:"refreshTokenLifeSpan"`
}
