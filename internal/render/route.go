package render

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
)

// Gateway API kinds, handled unstructured (no dependency), like Certificates.
const GatewayGroup = "gateway.networking.k8s.io"

var (
	GatewayGVK     = schema.GroupVersionKind{Group: GatewayGroup, Version: "v1", Kind: "Gateway"}
	HTTPRouteGVK   = schema.GroupVersionKind{Group: GatewayGroup, Version: "v1", Kind: "HTTPRoute"}
	ListenerSetGVK = schema.GroupVersionKind{Group: GatewayGroup, Version: "v1", Kind: "ListenerSet"}
)

// HostRouteLabel marks the shared per-host HTTPRoutes of Zones with a gateway.
const HostRouteLabel = "auth.w6d.io/host-route"

// ZoneListener is the listener name inside a Zone's ListenerSet.
const ZoneListener = "https"

// HostRouteName names the HTTPRoute of one host (the same name as its host
// Ingress: another kind, so both live side by side while a Zone migrates).
func HostRouteName(host string) string { return "host-" + Hash(host) }

// RouteParent is where a Zone's routes attach: its own ListenerSet (tls issuer
// or secret) or the Gateway itself (the listener's certificate).
func RouteParent(z *authv1.Zone, cfg *config.Config) map[string]any {
	if z.Spec.OwnListener() {
		return map[string]any{"group": GatewayGroup, "kind": "ListenerSet", "namespace": cfg.GatewayNamespace,
			"name": ZoneName(z), "sectionName": ZoneListener}
	}
	gw := z.Spec.Gateway
	p := map[string]any{"group": GatewayGroup, "kind": "Gateway", "namespace": gw.Namespace, "name": gw.Name}
	if gw.SectionName != "" {
		p["sectionName"] = gw.SectionName
	}
	return p
}

// HostRoute is the HTTPRoute of one host under a Zone with a gateway, shared by
// every Site on that host (each one an owner, none the controller, so it goes
// away with the last one): the fixed template — exactly that host, every path
// to the gateway Service, no filters. Path prefixes are the Rules' job, so one
// route serves every Site on the host. Owner references are set by the caller.
func HostRoute(host string, zone *authv1.Zone, cfg *config.Config) *unstructured.Unstructured {
	rule := map[string]any{
		"matches":     []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/"}}},
		"backendRefs": []any{map[string]any{"group": "", "kind": "Service", "name": cfg.GatewayService, "port": int64(cfg.GatewayServicePortNumber), "weight": int64(1)}},
	}
	if cfg.RouteRequestTimeout != "" {
		rule["timeouts"] = map[string]any{"request": cfg.RouteRequestTimeout}
	}
	spec := map[string]any{
		"parentRefs": []any{RouteParent(zone, cfg)},
		"hostnames":  []any{host},
		"rules":      []any{rule},
	}
	u := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	u.SetGroupVersionKind(HTTPRouteGVK)
	u.SetName(HostRouteName(host))
	u.SetNamespace(cfg.GatewayNamespace)
	u.SetLabels(map[string]string{ManagedByLabel: ManagedBy, HostRouteLabel: "true", ZoneLabel: zone.Name})
	u.SetAnnotations(map[string]string{SpecHashAnnotation: Hash(spec), HostAnnotation: host})
	return u
}

// ZoneListenerSet is the listener a Zone brings to its Gateway when it has its
// own certificate: *.<domain> on 443 with the Zone TLS Secret, routes from the
// gateway namespace only. It inherits every Gateway-level policy (WAF, CrowdSec).
func ZoneListenerSet(z *authv1.Zone, cfg *config.Config) *unstructured.Unstructured {
	gw := z.Spec.Gateway
	spec := map[string]any{
		"parentRef": map[string]any{"group": GatewayGroup, "kind": "Gateway", "namespace": gw.Namespace, "name": gw.Name},
		"listeners": []any{map[string]any{
			"name": ZoneListener, "port": int64(443), "protocol": "HTTPS", "hostname": "*." + z.Spec.Domain,
			"tls": map[string]any{"mode": "Terminate", "certificateRefs": []any{
				map[string]any{"group": "", "kind": "Secret", "name": ZoneSecret(z)},
			}},
			"allowedRoutes": map[string]any{"namespaces": map[string]any{"from": "Same"}},
		}},
	}
	om := zoneMeta(z, cfg, Hash(spec))
	u := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	u.SetGroupVersionKind(ListenerSetGVK)
	setMeta(u, om)
	return u
}

func setMeta(u *unstructured.Unstructured, om metav1.ObjectMeta) {
	u.SetName(om.Name)
	u.SetNamespace(om.Namespace)
	u.SetLabels(om.Labels)
	u.SetAnnotations(om.Annotations)
	u.SetOwnerReferences(om.OwnerReferences)
}
