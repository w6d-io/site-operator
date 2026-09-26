package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Gateway condition types.
const (
	GatewayConditionValidated = "Validated"
	GatewayConditionApplied   = "Applied"
	GatewayConditionRolled    = "Rolled"
	GatewayConditionReady     = "Ready"
)

// GatewayName is the only accepted name: one Gateway per gateway namespace.
const GatewayName = "default"

// Handler kinds (the Oathkeeper config sections) and every handler Oathkeeper
// v25.4.0 knows in each (spec/config.schema.json).
const (
	KindAuthenticators = "authenticators"
	KindAuthorizers    = "authorizers"
	KindMutators       = "mutators"
	KindErrors         = "errors"
)

// GatewayHandlers lists every handler per kind; the CRD enum rules mirror it.
var GatewayHandlers = map[string][]string{
	KindAuthenticators: {"anonymous", "bearer_token", "cookie_session", "jwt", "noop", "oauth2_client_credentials", "oauth2_introspection", "unauthorized"},
	KindAuthorizers:    {"allow", "deny", "keto_engine_acp_ory", "remote", "remote_json"},
	KindMutators:       {"cookie", "header", "hydrator", "id_token", "noop"},
	KindErrors:         {"json", "redirect", "www_authenticate"},
}

// GatewayHandler is one handler's global setting, as in the Oathkeeper config:
// Config is required by Oathkeeper for most handlers once enabled and is
// checked against Oathkeeper's own schema by the operator.
type GatewayHandler struct {
	Enabled bool `json:"enabled"`
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Schemaless
	// +kubebuilder:validation:Type=object
	Config *runtime.RawExtension `json:"config,omitempty"`
}

// GatewayErrors is the errors section: the handlers and the fallback order used
// when no rule error handler matches (and for "no rule matched").
type GatewayErrors struct {
	// +optional
	// +kubebuilder:validation:XValidation:rule="self.all(k, k in ['json', 'redirect', 'www_authenticate'])",message="unknown error handler"
	Handlers map[string]GatewayHandler `json:"handlers,omitempty"`
	// +optional
	// +kubebuilder:validation:items:Enum=json;redirect;www_authenticate
	Fallback []string `json:"fallback,omitempty"`
}

// GatewaySpec is the global handler configuration of the Oathkeeper gateway.
// Handlers left out are disabled. serve, log, access_rules and the rest of the
// Oathkeeper config stay with the platform chart (base config).
type GatewaySpec struct {
	// +optional
	// +kubebuilder:validation:XValidation:rule="self.all(k, k in ['anonymous', 'bearer_token', 'cookie_session', 'jwt', 'noop', 'oauth2_client_credentials', 'oauth2_introspection', 'unauthorized'])",message="unknown authenticator"
	Authenticators map[string]GatewayHandler `json:"authenticators,omitempty"`
	// +optional
	// +kubebuilder:validation:XValidation:rule="self.all(k, k in ['allow', 'deny', 'keto_engine_acp_ory', 'remote', 'remote_json'])",message="unknown authorizer"
	Authorizers map[string]GatewayHandler `json:"authorizers,omitempty"`
	// +optional
	// +kubebuilder:validation:XValidation:rule="self.all(k, k in ['cookie', 'header', 'hydrator', 'id_token', 'noop'])",message="unknown mutator"
	Mutators map[string]GatewayHandler `json:"mutators,omitempty"`
	// +optional
	Errors GatewayErrors `json:"errors,omitempty"`
}

// Handlers returns the handler map of one kind.
func (s *GatewaySpec) Handlers(kind string) map[string]GatewayHandler {
	switch kind {
	case KindAuthenticators:
		return s.Authenticators
	case KindAuthorizers:
		return s.Authorizers
	case KindMutators:
		return s.Mutators
	case KindErrors:
		return s.Errors.Handlers
	}
	return nil
}

// GatewayEnabled is the enabled handler set per kind.
type GatewayEnabled struct {
	// +optional
	Authenticators []string `json:"authenticators,omitempty"`
	// +optional
	Authorizers []string `json:"authorizers,omitempty"`
	// +optional
	Mutators []string `json:"mutators,omitempty"`
	// +optional
	Errors []string `json:"errors,omitempty"`
}

// HandlerUse lists who references one handler: Sites by name, other Rules
// (platform, legacy) as "rule/<name>".
type HandlerUse struct {
	// Handler is "<kind>/<name>", e.g. authenticators/cookie_session.
	Handler string   `json:"handler"`
	UsedBy  []string `json:"usedBy"`
}

// GatewayStatus is written by the operator only.
type GatewayStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// Enabled is the handler set live on every gateway pod (after a successful
	// rollout); Site validation reads it.
	// +optional
	Enabled *GatewayEnabled `json:"enabled,omitempty"`
	// InUse lists every handler referenced by a live Rule.
	// +optional
	InUse []HandlerUse `json:"inUse,omitempty"`
	// ConfigHash is the hash of the rendered Oathkeeper config serving now
	// (empty while the chart's seed config serves).
	// +optional
	ConfigHash string `json:"configHash,omitempty"`
	// ConfigMap is the config ConfigMap that last rolled out and loaded every
	// rule: what serves now, and the rollback target.
	// +optional
	ConfigMap string `json:"configMap,omitempty"`
	// Revisions are the versioned config ConfigMaps the operator created, newest
	// first; beyond the last 3, those neither in use nor last good are deleted.
	// +optional
	Revisions []string `json:"revisions,omitempty"`
	// FailedHash is a rendered config that failed to roll out and was rolled
	// back; it is not retried until the spec changes.
	// +optional
	FailedHash string `json:"failedHash,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Config",type=string,JSONPath=`.status.configHash`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Gateway is the global Oathkeeper handler configuration (one per gateway
// namespace, named "default"). jinbe writes it; the operator renders it into the
// Oathkeeper config and rolls the gateway.
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="the Gateway is a singleton named default"
type Gateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GatewaySpec   `json:"spec,omitempty"`
	Status GatewayStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GatewayList contains a list of Gateway.
type GatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Gateway `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Gateway{}, &GatewayList{})
}
