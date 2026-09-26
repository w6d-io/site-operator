package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ZoneTLSMode says where the wildcard certificate of a Zone comes from.
// +kubebuilder:validation:Enum=default;secret;issuer
type ZoneTLSMode string

const (
	// ZoneTLSDefault relies on the ingress controller's default certificate (no tls block).
	ZoneTLSDefault ZoneTLSMode = "default"
	// ZoneTLSSecret uses an existing TLS Secret in the gateway namespace.
	ZoneTLSSecret ZoneTLSMode = "secret"
	// ZoneTLSIssuer makes the operator request a wildcard Certificate (DNS-01 issuer).
	ZoneTLSIssuer ZoneTLSMode = "issuer"
)

// ZoneIngressMode says how the Zone's hosts reach the gateway.
// +kubebuilder:validation:Enum=wildcard;per-site
type ZoneIngressMode string

const (
	// ZoneIngressWildcard: one wildcard Ingress *.<domain> serves every Site host.
	ZoneIngressWildcard ZoneIngressMode = "wildcard"
	// ZoneIngressPerSite: no wildcard Ingress; each Site gets its own exact-host
	// Ingress, created only when no other Ingress in the cluster serves the host.
	ZoneIngressPerSite ZoneIngressMode = "per-site"
)

// ZoneTLS configures HTTPS for every host of the Zone.
// +kubebuilder:validation:XValidation:rule="self.mode != 'secret' || (has(self.secretName) && size(self.secretName) > 0)",message="mode secret needs secretName"
type ZoneTLS struct {
	// +optional
	// +kubebuilder:default=default
	Mode ZoneTLSMode `json:"mode,omitempty"`
	// SecretName of an existing TLS Secret in the gateway namespace (mode secret).
	// +optional
	SecretName string `json:"secretName,omitempty"`
	// Issuer is the ClusterIssuer for mode issuer; empty uses the operator default.
	// +optional
	Issuer string `json:"issuer,omitempty"`
}

// ZoneSpec is an admin-defined wildcard domain: any Site host that is one label
// under Domain is served by the Zone's single wildcard Ingress.
type ZoneSpec struct {
	// Domain without the leading "*.", e.g. dev.example.com.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="domain is immutable; create another Zone"
	Domain string `json:"domain"`
	// IngressClass must be one the operator allows; empty uses the operator default.
	// +optional
	IngressClass string `json:"ingressClass,omitempty"`
	// +optional
	// +kubebuilder:default={mode: default}
	TLS ZoneTLS `json:"tls,omitempty"`
	// Ingress is wildcard (default: one *.<domain> Ingress) or per-site (one
	// exact-host Ingress per Site, for a domain other Ingresses already use).
	// +optional
	// +kubebuilder:default=wildcard
	Ingress ZoneIngressMode `json:"ingress,omitempty"`
}

// PerSite reports whether each Site under the Zone gets its own Ingress.
func (s ZoneSpec) PerSite() bool { return s.Ingress == ZoneIngressPerSite }

// ZoneStatus is written by the operator only.
type ZoneStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Domain",type=string,JSONPath=`.spec.domain`
// +kubebuilder:printcolumn:name="Ingress",type=string,JSONPath=`.spec.ingress`
// +kubebuilder:printcolumn:name="TLS",type=string,JSONPath=`.spec.tls.mode`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Zone is a wildcard domain the platform serves; defined by cluster admins.
// +kubebuilder:validation:XValidation:rule="self.metadata.name.size() <= 50",message="zone names are at most 50 characters"
type Zone struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ZoneSpec   `json:"spec,omitempty"`
	Status ZoneStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ZoneList contains a list of Zone.
type ZoneList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Zone `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Zone{}, &ZoneList{})
}
