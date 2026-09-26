package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Condition types reported on Site.status.conditions.
const (
	ConditionValidated        = "Validated"
	ConditionRulesSynced      = "RulesSynced"
	ConditionRulesLoaded      = "RulesLoaded"
	ConditionIngressReady     = "IngressReady"
	ConditionCertificateReady = "CertificateReady"
	ConditionReady            = "Ready"
	// ConditionHostShadowsWildcard (a warning, not part of Ready): the Site's own
	// exact-host Ingress overrides a wildcard Ingress elsewhere for its hosts.
	ConditionHostShadowsWildcard = "HostShadowsWildcard"
)

// TLSMode says how HTTPS is served for the Site's hosts.
// +kubebuilder:validation:Enum=wildcard;per-site
type TLSMode string

const (
	// TLSWildcard relies on the ingress controller's default wildcard certificate.
	TLSWildcard TLSMode = "wildcard"
	// TLSPerSite makes the operator request a dedicated cert-manager Certificate.
	TLSPerSite TLSMode = "per-site"
)

// Upstream is the in-cluster Service matching requests are forwarded to. It is
// structured (never a free URL) so no Site can point at an arbitrary address.
// +kubebuilder:validation:XValidation:rule="!(self.namespace in ['kube-system','kube-public','kube-node-lease','cert-manager','ingress-nginx','argocd','vault','gatekeeper-system'])",message="upstream namespace is a platform namespace"
type Upstream struct {
	// +kubebuilder:validation:Pattern=`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`
	Service string `json:"service"`
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
	Namespace string `json:"namespace"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
	// +optional
	// +kubebuilder:validation:Enum=http;https
	// +kubebuilder:default=http
	Scheme string `json:"scheme,omitempty"`
	// +optional
	PreserveHost bool `json:"preserveHost,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^/[^\s]*$`
	StripPath string `json:"stripPath,omitempty"`
}

// Handler is one Oathkeeper pipeline handler with its per-rule config.
type Handler struct {
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9_]{0,63}$`
	Handler string `json:"handler"`
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:validation:Type=object
	Config *runtime.RawExtension `json:"config,omitempty"`
}

// Match is the Oathkeeper rule match block (regexp strategy).
type Match struct {
	// URL is the Oathkeeper match pattern; regex parts go inside <...>.
	// It must start with a scheme and one of the Site hosts followed by "/".
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	URL string `json:"url"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:Enum=GET;HEAD;POST;PUT;PATCH;DELETE;OPTIONS;CONNECT;TRACE
	Methods []string `json:"methods"`
}

// Gate is one Oathkeeper rule: how callers prove who they are, how access is
// checked, what the upstream receives and how failures are answered.
type Gate struct {
	// Name is unique inside the Site and becomes part of the Rule name.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`
	Name  string `json:"name"`
	Match Match  `json:"match"`
	// +kubebuilder:validation:MinItems=1
	Authenticators []Handler `json:"authenticators"`
	Authorizer     Handler   `json:"authorizer"`
	// +optional
	Mutators []Handler `json:"mutators,omitempty"`
	// +optional
	Errors []Handler `json:"errors,omitempty"`
	// Upstream overrides the Site upstream for this gate.
	// +optional
	Upstream *Upstream `json:"upstream,omitempty"`
}

// ExposureMode says how a Site's hosts reach the gateway.
// +kubebuilder:validation:Enum=zone;vanity
type ExposureMode string

const (
	// ExposureZone: the Zone's wildcard Ingress serves the hosts; the Site renders rules only.
	ExposureZone ExposureMode = "zone"
	// ExposureVanity (opt-in): the Site also gets its own Ingress from the fixed template.
	ExposureVanity ExposureMode = "vanity"
)

// Exposure describes the public entry point. A host under a Zone is served by
// the Zone's wildcard Ingress, so by default a Site renders rules only.
type Exposure struct {
	// +optional
	// +kubebuilder:default=zone
	Mode ExposureMode `json:"mode,omitempty"`
	// IngressClass must be one the operator allows; empty uses the operator default.
	// +optional
	IngressClass string `json:"ingressClass,omitempty"`
	// TLS for the vanity Ingress: wildcard (no tls block, zone/default certificate) or per-site (own Certificate).
	// +optional
	// +kubebuilder:default=wildcard
	TLS TLSMode `json:"tls,omitempty"`
	// Issuer is the cert-manager ClusterIssuer for per-site certificates; empty uses the operator default.
	// +optional
	Issuer string `json:"issuer,omitempty"`
}

// SiteSpec is the rendered gateway/exposure part of a site's intent (written by jinbe).
type SiteSpec struct {
	// Hosts are each exactly one DNS label under a Zone domain.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`
	Hosts    []string `json:"hosts"`
	Upstream Upstream `json:"upstream"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=name
	Gates []Gate `json:"gates"`
	// +optional
	Exposure Exposure `json:"exposure,omitempty"`
	// Paused removes every child object; the status is kept.
	// +optional
	Paused bool `json:"paused,omitempty"`
	// System marks a platform-owned site rendered by the chart (read-only in kuma).
	// +optional
	System bool `json:"system,omitempty"`
}

// Child is one object the operator rendered for the Site.
type Child struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	SpecHash string `json:"specHash"`
}

// SiteStatus is written by the operator only.
type SiteStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// +optional
	Children []Child `json:"children,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Hosts",type=string,JSONPath=`.spec.hosts`
// +kubebuilder:printcolumn:name="Paused",type=boolean,JSONPath=`.spec.paused`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Site is a website or API plugged behind the platform gateway.
// +kubebuilder:validation:XValidation:rule="self.metadata.name.size() <= 40",message="site names are at most 40 characters (child names embed them)"
type Site struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SiteSpec   `json:"spec,omitempty"`
	Status SiteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SiteList contains a list of Site.
type SiteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Site `json:"items"`
}

// Vanity reports whether the Site asks for its own Ingress.
func (e Exposure) Vanity() bool { return e.Mode == ExposureVanity }

func init() {
	SchemeBuilder.Register(&Site{}, &SiteList{})
}
