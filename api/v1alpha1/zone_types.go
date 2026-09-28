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

// ZoneIngressMode says how the Zone's hosts reach the gateway through the ingress controller.
// +kubebuilder:validation:Enum=wildcard;per-site;none
type ZoneIngressMode string

const (
	// ZoneIngressWildcard: one wildcard Ingress *.<domain> serves every Site host.
	ZoneIngressWildcard ZoneIngressMode = "wildcard"
	// ZoneIngressPerSite: no wildcard Ingress; each Site gets its own exact-host
	// Ingress, created only when no other Ingress in the cluster serves the host.
	ZoneIngressPerSite ZoneIngressMode = "per-site"
	// ZoneIngressNone: no Ingress at all; the Zone's Gateway API Gateway is the only entry point.
	ZoneIngressNone ZoneIngressMode = "none"
)

// ZoneGateway is the Gateway API Gateway (not the Oathkeeper Gateway) a Zone's
// hosts are attached to: one HTTPRoute per host, behind the Gateway's policies
// (WAF, CrowdSec). It must be one the operator allows (--gateways).
type ZoneGateway struct {
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	Namespace string `json:"namespace"`
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`
	Name string `json:"name"`
	// SectionName pins the listener (tls mode default); empty lets the Gateway
	// pick the HTTPS listener whose hostname covers the Zone.
	// +optional
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,251}[a-z0-9])?$`
	SectionName string `json:"sectionName,omitempty"`
}

// Key is namespace/name, the form of the operator's --gateways list.
func (g ZoneGateway) Key() string { return g.Namespace + "/" + g.Name }

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
// under Domain is served by the Zone's entry points: an Ingress (wildcard or per
// site) and/or a Gateway API Gateway (one HTTPRoute per host). Both at once is
// the migration state: add the gateway, move DNS, then set ingress none.
// +kubebuilder:validation:XValidation:rule="!has(self.ingress) || self.ingress != 'none' || has(self.gateway)",message="ingress none needs a gateway: a zone needs an entry point"
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
	// Ingress is wildcard (default: one *.<domain> Ingress), per-site (one
	// exact-host Ingress per Site, for a domain other Ingresses already use) or
	// none (the gateway alone serves the Zone).
	// +optional
	// +kubebuilder:default=wildcard
	Ingress ZoneIngressMode `json:"ingress,omitempty"`
	// Gateway attaches every Site host of the Zone to a Gateway API Gateway.
	// +optional
	Gateway *ZoneGateway `json:"gateway,omitempty"`
}

// PerSite reports whether each Site under the Zone gets its own Ingress.
func (s ZoneSpec) PerSite() bool { return s.Ingress == ZoneIngressPerSite }

// NoIngress reports whether the Zone has no Ingress at all.
func (s ZoneSpec) NoIngress() bool { return s.Ingress == ZoneIngressNone }

// Routed reports whether the Zone's hosts get HTTPRoutes on a Gateway.
func (s ZoneSpec) Routed() bool { return s.Gateway != nil }

// OwnListener reports whether a routed Zone brings its own listener (a
// ListenerSet with the Zone certificate) instead of using the Gateway's.
func (s ZoneSpec) OwnListener() bool {
	return s.Routed() && (s.TLS.Mode == ZoneTLSIssuer || s.TLS.Mode == ZoneTLSSecret)
}

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
// +kubebuilder:printcolumn:name="Gateway",type=string,JSONPath=`.spec.gateway.name`
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
