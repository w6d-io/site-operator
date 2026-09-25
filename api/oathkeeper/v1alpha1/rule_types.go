// Package v1alpha1 mirrors the oathkeeper-maester Rule API (oathkeeper.ory.sh/v1alpha1).
// Only the fields the operator writes or reads are declared; the CRD itself is
// vendored in config/crd/external.
// +kubebuilder:object:generate=true
// +kubebuilder:skip
// +groupName=oathkeeper.ory.sh
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	GroupVersion  = schema.GroupVersion{Group: "oathkeeper.ory.sh", Version: "v1alpha1"}
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
	AddToScheme   = SchemeBuilder.AddToScheme
)

type Handler struct {
	Handler string                `json:"handler"`
	Config  *runtime.RawExtension `json:"config,omitempty"`
}

type Match struct {
	URL     string   `json:"url"`
	Methods []string `json:"methods"`
}

type Upstream struct {
	URL          string  `json:"url"`
	PreserveHost *bool   `json:"preserveHost,omitempty"`
	StripPath    *string `json:"stripPath,omitempty"`
}

type RuleSpec struct {
	Upstream       *Upstream  `json:"upstream,omitempty"`
	Match          *Match     `json:"match"`
	Authenticators []*Handler `json:"authenticators,omitempty"`
	Authorizer     *Handler   `json:"authorizer,omitempty"`
	Mutators       []*Handler `json:"mutators,omitempty"`
	Errors         []*Handler `json:"errors,omitempty"`
	ConfigMapName  *string    `json:"configMapName,omitempty"`
}

type Validation struct {
	Valid           *bool   `json:"valid,omitempty"`
	ValidationError *string `json:"validationError,omitempty"`
}

type RuleStatus struct {
	Validation *Validation `json:"validation,omitempty"`
}

// +kubebuilder:object:root=true

// Rule has no status subresource upstream: maester writes status with a plain update.
type Rule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RuleSpec   `json:"spec,omitempty"`
	Status RuleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type RuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Rule `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Rule{}, &RuleList{})
}
