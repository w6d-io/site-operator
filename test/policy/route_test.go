package policy

import (
	"strings"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	routeGVK       = schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"}
	listenerSetGVK = schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "ListenerSet"}
	eg             = map[string]any{"name": "eg", "namespace": "envoy-gateway-system"}
)

// grantGateway gives the intruder full RBAC on Gateway API and Envoy Gateway
// objects in auth, so its requests reach the admission policies.
func grantGateway(t *testing.T) {
	t.Helper()
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "auth"},
		Rules: []rbacv1.PolicyRule{{APIGroups: []string{"gateway.networking.k8s.io", "gateway.envoyproxy.io"}, Resources: []string{"*"}, Verbs: []string{"*"}}}}
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "auth"},
		RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "test-gateway"},
		Subjects: []rbacv1.Subject{{Kind: "User", Name: intruderUser}}}
	for _, o := range []client.Object{role, rb} {
		if err := admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = admin.Delete(ctx, rb); _ = admin.Delete(ctx, role) })
}

func obj(gvk schema.GroupVersionKind, name string, spec map[string]any, labels, ann map[string]string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	u.SetGroupVersionKind(gvk)
	u.SetNamespace("auth")
	u.SetName(name)
	u.SetLabels(labels)
	u.SetAnnotations(ann)
	return u
}

func route(name string, parent map[string]any, backend string, hosts ...string) *unstructured.Unstructured {
	hs := []any{}
	for _, h := range hosts {
		hs = append(hs, h)
	}
	return obj(routeGVK, name, map[string]any{"parentRefs": []any{parent}, "hostnames": hs,
		"rules": []any{map[string]any{"backendRefs": []any{map[string]any{"name": backend, "port": int64(4455)}}}}}, nil, nil)
}

// hostRoute is the operator's template: host-<hash8>, one host, Site owners.
func hostRoute(name, host string, owners ...string) *unstructured.Unstructured {
	rt := route(name, eg, "auth-oathkeeper-proxy", host)
	rt.SetLabels(map[string]string{"app.kubernetes.io/managed-by": "site-operator", "auth.w6d.io/host-route": "true"})
	rt.SetAnnotations(map[string]string{"auth.w6d.io/host": host, "auth.w6d.io/spec-hash": "abcd1234"})
	var refs []metav1.OwnerReference
	for _, o := range owners {
		refs = append(refs, metav1.OwnerReference{APIVersion: "auth.w6d.io/v1alpha1", Kind: "Site", Name: o, UID: k8stypes.UID("u-" + o)})
	}
	rt.SetOwnerReferences(refs)
	return rt
}

func listenerSet(name, hostname, secret string, parent map[string]any, labels map[string]string) *unstructured.Unstructured {
	return obj(listenerSetGVK, name, map[string]any{"parentRef": parent, "listeners": []any{map[string]any{
		"name": "https", "port": int64(443), "protocol": "HTTPS", "hostname": hostname,
		"tls": map[string]any{"mode": "Terminate", "certificateRefs": []any{map[string]any{"kind": "Secret", "name": secret}}}}}}, labels, nil)
}

// TestRoutePolicy: every HTTPRoute of the gateway namespace goes to the
// oathkeeper proxy through an allowed Gateway; the operator's routes and
// ListenerSets match their templates and hosts are under a Zone.
func TestRoutePolicy(t *testing.T) {
	grantGateway(t)
	setZonesAndSecrets("dev.example.com", "dev-wildcard")
	t.Cleanup(func() { setZones("dev.example.com") })
	proxy := "auth-oathkeeper-proxy"

	denied(t, intruder, route("steal", eg, "auth-kratos-admin", "steal.dev.example.com"), "must be the Service auth-oathkeeper-proxy")
	other := map[string]any{"name": "internal", "namespace": "envoy-gateway-system"}
	denied(t, intruder, route("bypass", other, proxy, "bypass.dev.example.com"), "attaches only to envoy-gateway-system/eg")
	denied(t, intruder, route("same-ns", map[string]any{"name": "eg"}, proxy, "x.dev.example.com"), "attaches only to")
	mirror := route("mirror", eg, proxy, "mirror.dev.example.com")
	mirror.Object["spec"].(map[string]any)["rules"].([]any)[0].(map[string]any)["filters"] = []any{map[string]any{"type": "RequestMirror",
		"requestMirror": map[string]any{"backendRef": map[string]any{"name": "sniffer", "port": int64(80)}}}}
	denied(t, intruder, mirror, "RequestMirror and ExtensionRef")
	crossNs := route("cross", eg, proxy, "cross.dev.example.com")
	crossNs.Object["spec"].(map[string]any)["rules"].([]any)[0].(map[string]any)["backendRefs"].([]any)[0].(map[string]any)["namespace"] = "shop"
	denied(t, intruder, crossNs, "must be the Service auth-oathkeeper-proxy")

	// the chart's own route (auth.qualif on dev-aws-1) keeps working
	allowed(t, intruder, route("kratos-example-auth-ui", eg, proxy, "auth.qualif.example.com"))

	// operator routes: host-<hash8>, one host under a Zone = its annotation, Site owners only, no filters
	allowed(t, operator, hostRoute("host-0123abcd", "shop.dev.example.com", "shop", "shop-api"))
	denied(t, operator, hostRoute("host-0123abce", "far.example.com", "shop"), "one host under a Zone")
	denied(t, operator, hostRoute("host-0123abcf", "orphan.dev.example.com"), "one host under a Zone")
	two := hostRoute("host-0123abd0", "a.dev.example.com", "shop")
	two.Object["spec"].(map[string]any)["hostnames"] = []any{"a.dev.example.com", "b.dev.example.com"}
	denied(t, operator, two, "one host under a Zone")
	lie := hostRoute("host-0123abd1", "c.dev.example.com", "shop")
	lie.SetAnnotations(map[string]string{"auth.w6d.io/host": "d.dev.example.com"})
	denied(t, operator, lie, "one host under a Zone")
	rogue := route("rogue", eg, proxy, "rogue.dev.example.com")
	denied(t, operator, rogue, "operator HTTPRoutes are named host-<hash>")
	filtered := hostRoute("host-0123abd2", "e.dev.example.com", "shop")
	filtered.Object["spec"].(map[string]any)["rules"].([]any)[0].(map[string]any)["filters"] = []any{map[string]any{"type": "RequestHeaderModifier",
		"requestHeaderModifier": map[string]any{"set": []any{map[string]any{"name": "X-User-Id", "value": "admin"}}}}}
	denied(t, operator, filtered, "an operator HTTPRoute has no filters")
	chart := &unstructured.Unstructured{}
	chart.SetGroupVersionKind(routeGVK)
	if err := operator.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "kratos-example-auth-ui"}, chart); err != nil {
		t.Fatal(err)
	}
	if err := operator.Delete(ctx, chart); err == nil || !strings.Contains(err.Error(), "operator HTTPRoutes are named host-<hash>") {
		t.Fatalf("operator deleted the chart route: %v", err)
	}

	// ListenerSets: an allowed Gateway; the operator's are zone-*, *.<zone domain>, a Zone Secret
	zoneLS := func(name, host, secret string) *unstructured.Unstructured {
		return listenerSet(name, host, secret, eg, map[string]string{"app.kubernetes.io/managed-by": "site-operator"})
	}
	denied(t, intruder, listenerSet("elsewhere", "x.dev.example.com", "x-tls", other, nil), "a ListenerSet here attaches only to envoy-gateway-system/eg")
	allowed(t, operator, zoneLS("zone-dev", "*.dev.example.com", "dev-wildcard"))
	denied(t, operator, zoneLS("zone-evil", "*.evil.com", "dev-wildcard"), "wildcard of a Zone domain")
	denied(t, operator, zoneLS("zone-thief", "*.dev.example.com", "auth-kratos-tls"), "uses a Zone TLS Secret")
	denied(t, operator, zoneLS("listener", "*.dev.example.com", "dev-wildcard"), "its ListenerSets zone-<name>")
	open := zoneLS("zone-open", "*.dev.example.com", "dev-wildcard")
	open.Object["spec"].(map[string]any)["listeners"].([]any)[0].(map[string]any)["allowedRoutes"] = map[string]any{"namespaces": map[string]any{"from": "All"}}
	denied(t, operator, open, "takes routes from its own namespace only")
}

var (
	securityGVK  = schema.GroupVersionKind{Group: "gateway.envoyproxy.io", Version: "v1alpha1", Kind: "SecurityPolicy"}
	extensionGVK = schema.GroupVersionKind{Group: "gateway.envoyproxy.io", Version: "v1alpha1", Kind: "EnvoyExtensionPolicy"}
)

func target(kind, name string) map[string]any {
	return map[string]any{"group": "gateway.networking.k8s.io", "kind": kind, "name": name}
}

// TestRouteLevelPoliciesKeepTheWAF: nothing in the gateway namespace replaces
// the Gateway's WAF (EnvoyExtensionPolicy) or denylist + CrowdSec (a
// SecurityPolicy without mergeType), nor touches the operator's routes.
func TestRouteLevelPoliciesKeepTheWAF(t *testing.T) {
	grantGateway(t)
	cors := map[string]any{"allowOrigins": []any{"https://auth.qualif.example.com"}}
	denied(t, intruder, obj(extensionGVK, "no-waf", map[string]any{"targetRefs": []any{target("HTTPRoute", "kratos-example-auth-ui")},
		"wasm": []any{}}, nil, nil), "no EnvoyExtensionPolicy in the gateway namespace")
	denied(t, intruder, obj(securityGVK, "replace", map[string]any{"targetRefs": []any{target("HTTPRoute", "kratos-example-auth-ui")},
		"cors": cors}, nil, nil), "sets mergeType")
	denied(t, intruder, obj(securityGVK, "select", map[string]any{"mergeType": "StrategicMerge",
		"targetSelectors": []any{map[string]any{"kind": "HTTPRoute", "matchLabels": map[string]any{"auth.w6d.io/host-route": "true"}}}, "cors": cors}, nil, nil),
		"no targetSelectors")
	denied(t, intruder, obj(securityGVK, "hijack", map[string]any{"mergeType": "StrategicMerge",
		"targetRefs": []any{target("HTTPRoute", "host-0123abcd")}, "cors": cors}, nil, nil), "may not target the site-operator's routes")
	denied(t, intruder, obj(securityGVK, "hijack-ls", map[string]any{"mergeType": "StrategicMerge",
		"targetRef": target("ListenerSet", "zone-dev"), "cors": cors}, nil, nil), "may not target the site-operator's routes")

	// the chart's CORS policy (kratos-example on dev-aws-1) merges: allowed
	allowed(t, intruder, obj(securityGVK, "kratos-example-auth-ui-cors", map[string]any{"mergeType": "StrategicMerge",
		"targetRefs": []any{target("HTTPRoute", "kratos-example-auth-ui")}, "cors": cors}, nil, nil))
	allowed(t, admin, obj(extensionGVK, "platform", map[string]any{"targetRefs": []any{target("HTTPRoute", "kratos-example-auth-ui")}}, nil, nil))
}

// Gateway API: the operator writes routes and ListenerSets only in the gateway
// namespace and reads Gateways, routes and ListenerSets cluster-wide; jinbe writes none.
func TestGatewayAPIScope(t *testing.T) {
	for _, c := range []struct {
		user, ns, verb, resource string
		want                     bool
	}{
		{operatorUser, "auth", "create", "httproutes", true},
		{operatorUser, "auth", "delete", "listenersets", true},
		{operatorUser, "legacy", "list", "httproutes", true},
		{operatorUser, "legacy", "watch", "listenersets", true},
		{operatorUser, "envoy-gateway-system", "get", "gateways", true},
		{operatorUser, "legacy", "create", "httproutes", false},
		{operatorUser, "envoy-gateway-system", "update", "gateways", false},
		{operatorUser, "auth", "create", "gateways", false},
		{jinbeUser, "auth", "create", "httproutes", false},
		{jinbeUser, "auth", "create", "listenersets", false},
	} {
		sar := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
			User: c.user, Groups: []string{"system:serviceaccounts", "system:authenticated"},
			ResourceAttributes: &authzv1.ResourceAttributes{Namespace: c.ns, Verb: c.verb, Group: "gateway.networking.k8s.io", Resource: c.resource},
		}}
		if err := admin.Create(ctx, sar); err != nil {
			t.Fatal(err)
		}
		if sar.Status.Allowed != c.want {
			t.Errorf("%s %s %s in %q: got %v want %v", c.user, c.verb, c.resource, c.ns, sar.Status.Allowed, c.want)
		}
	}
}
