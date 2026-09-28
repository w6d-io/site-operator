package render

import (
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
)

func gatewayZone(tls authv1.ZoneTLS) *authv1.Zone {
	return &authv1.Zone{ObjectMeta: metav1.ObjectMeta{Name: "dev", UID: "zone-uid"},
		Spec: authv1.ZoneSpec{Domain: "dev.example.com", Ingress: authv1.ZoneIngressNone, TLS: tls,
			Gateway: &authv1.ZoneGateway{Namespace: "envoy-gateway-system", Name: "eg"}}}
}

func js(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestHostRouteIsFixedTemplate: one exact host, every path to the gateway
// Service by port number, the request timeout from the config, no filters,
// attached to the Zone's Gateway; named like the host Ingress.
func TestHostRouteIsFixedTemplate(t *testing.T) {
	cfg := config.Default()
	z := gatewayZone(authv1.ZoneTLS{Mode: authv1.ZoneTLSDefault})
	rt := HostRoute("shop.dev.example.com", z, cfg)
	if rt.GetName() != HostIngressName("shop.dev.example.com") || rt.GetNamespace() != "auth" || rt.GetKind() != "HTTPRoute" {
		t.Fatalf("meta %s/%s %s", rt.GetNamespace(), rt.GetName(), rt.GetKind())
	}
	if l := rt.GetLabels(); l[ManagedByLabel] != ManagedBy || l[HostRouteLabel] != "true" || l[ZoneLabel] != "dev" {
		t.Fatalf("labels %v", l)
	}
	if a := rt.GetAnnotations(); a[HostAnnotation] != "shop.dev.example.com" || a[SpecHashAnnotation] == "" {
		t.Fatalf("annotations %v", a)
	}
	want := `{"hostnames":["shop.dev.example.com"],` +
		`"parentRefs":[{"group":"gateway.networking.k8s.io","kind":"Gateway","name":"eg","namespace":"envoy-gateway-system"}],` +
		`"rules":[{"backendRefs":[{"group":"","kind":"Service","name":"auth-oathkeeper-proxy","port":4455,"weight":1}],` +
		`"matches":[{"path":{"type":"PathPrefix","value":"/"}}],"timeouts":{"request":"300s"}}]}`
	if got := js(t, rt.Object["spec"]); got != want {
		t.Fatalf("spec\n got %s\nwant %s", got, want)
	}
	if len(rt.GetOwnerReferences()) != 0 {
		t.Fatal("owners are set by the controller (every Site on the host)")
	}

	// a pinned listener, no timeout
	z.Spec.Gateway.SectionName = "dev-example-https"
	cfg.RouteRequestTimeout = ""
	rt2 := HostRoute("shop.dev.example.com", z, cfg)
	if got := js(t, rt2.Object["spec"].(map[string]any)["parentRefs"]); got !=
		`[{"group":"gateway.networking.k8s.io","kind":"Gateway","name":"eg","namespace":"envoy-gateway-system","sectionName":"dev-example-https"}]` {
		t.Fatalf("parentRefs %s", got)
	}
	if _, ok := rt2.Object["spec"].(map[string]any)["rules"].([]any)[0].(map[string]any)["timeouts"]; ok {
		t.Fatal("no timeout configured: none rendered")
	}
	if rt2.GetAnnotations()[SpecHashAnnotation] == rt.GetAnnotations()[SpecHashAnnotation] {
		t.Fatal("the spec hash follows the spec")
	}
}

// TestZoneListenerSet: a Zone with its own certificate brings *.<domain> to
// the Gateway through a ListenerSet (Zone-owned, same-namespace routes only),
// and its routes attach to that listener.
func TestZoneListenerSet(t *testing.T) {
	cfg := config.Default()
	z := gatewayZone(authv1.ZoneTLS{Mode: authv1.ZoneTLSIssuer})
	z.Spec.Domain = "authdev.dev.example.com"
	ls := ZoneListenerSet(z, cfg)
	if ls.GetName() != "zone-dev" || ls.GetNamespace() != "auth" || ls.GetKind() != "ListenerSet" {
		t.Fatalf("meta %s/%s %s", ls.GetNamespace(), ls.GetName(), ls.GetKind())
	}
	if o := ls.GetOwnerReferences(); len(o) != 1 || o[0].Kind != "Zone" || o[0].UID != "zone-uid" || !*o[0].Controller {
		t.Fatalf("owner %+v", o)
	}
	want := `{"listeners":[{"allowedRoutes":{"namespaces":{"from":"Same"}},"hostname":"*.authdev.dev.example.com","name":"https","port":443,` +
		`"protocol":"HTTPS","tls":{"certificateRefs":[{"group":"","kind":"Secret","name":"zone-dev-tls"}],"mode":"Terminate"}}],` +
		`"parentRef":{"group":"gateway.networking.k8s.io","kind":"Gateway","name":"eg","namespace":"envoy-gateway-system"}}`
	if got := js(t, ls.Object["spec"]); got != want {
		t.Fatalf("spec\n got %s\nwant %s", got, want)
	}
	rt := HostRoute("kuma.authdev.dev.example.com", z, cfg)
	if got := js(t, rt.Object["spec"].(map[string]any)["parentRefs"]); got !=
		`[{"group":"gateway.networking.k8s.io","kind":"ListenerSet","name":"zone-dev","namespace":"auth","sectionName":"https"}]` {
		t.Fatalf("parentRefs %s", got)
	}
	if !z.Spec.OwnListener() || gatewayZone(authv1.ZoneTLS{Mode: authv1.ZoneTLSDefault}).Spec.OwnListener() {
		t.Fatal("own listener only for tls issuer/secret")
	}
}
