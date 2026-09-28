package controller

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/render"
)

const egNamespace = "envoy-gateway-system"

func condList(types ...string) []any {
	var out []any
	for _, t := range types {
		out = append(out, map[string]any{"type": t, "status": "True", "reason": t, "message": t,
			"lastTransitionTime": time.Now().UTC().Format(time.RFC3339)})
	}
	return out
}

// setupEnvoyGateway creates Gateway envoy-gateway-system/eg the way dev-aws-1
// has it (HTTPS wildcard listeners, routes from every namespace) and plays EG:
// programmed, with an address and programmed listeners.
func setupEnvoyGateway(ctx context.Context) error {
	if err := k8s.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: egNamespace}}); err != nil {
		return err
	}
	var listeners, statuses []any
	for _, l := range []struct{ name, host string }{{"gw-https", "gw.example.com"}, {"mv-https", "mv.example.com"}} {
		listeners = append(listeners, map[string]any{"name": l.name, "port": int64(443), "protocol": "HTTPS", "hostname": "*." + l.host,
			"tls":           map[string]any{"mode": "Terminate", "certificateRefs": []any{map[string]any{"kind": "Secret", "name": l.name + "-tls"}}},
			"allowedRoutes": map[string]any{"namespaces": map[string]any{"from": "All"}}})
		statuses = append(statuses, map[string]any{"name": l.name, "attachedRoutes": int64(0), "conditions": condList("Programmed", "Accepted"),
			"supportedKinds": []any{map[string]any{"group": render.GatewayGroup, "kind": "HTTPRoute"}}})
	}
	gw := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"gatewayClassName": "eg", "listeners": listeners}}}
	gw.SetGroupVersionKind(render.GatewayGVK)
	gw.SetNamespace(egNamespace)
	gw.SetName("eg")
	if err := k8s.Create(ctx, gw); err != nil {
		return err
	}
	gw.Object["status"] = map[string]any{"conditions": condList("Programmed", "Accepted"), "listeners": statuses,
		"addresses": []any{map[string]any{"type": "Hostname", "value": "envoy.elb.amazonaws.com"}}}
	return k8s.Status().Update(ctx, gw)
}

func routeOf(name string) (*unstructured.Unstructured, error) {
	rt := newRoute()
	return rt, k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: name}, rt)
}

// acceptRoute plays EG accepting a host route on its parent.
func acceptRoute(t *testing.T, name string) {
	t.Helper()
	eventually(t, "accept "+name, func() error {
		rt, err := routeOf(name)
		if err != nil {
			return err
		}
		refs, _, _ := unstructured.NestedSlice(rt.Object, "spec", "parentRefs")
		rt.Object["status"] = map[string]any{"parents": []any{map[string]any{"parentRef": refs[0],
			"controllerName": "gateway.envoyproxy.io/gatewayclass-controller", "conditions": condList("Accepted", "ResolvedRefs")}}}
		return k8s.Status().Update(ctx, rt)
	})
}

func routeGone(t *testing.T, name string) {
	t.Helper()
	eventually(t, "HTTPRoute "+name+" deleted", func() error {
		if _, err := routeOf(name); !apierrors.IsNotFound(err) {
			return fmt.Errorf("still there: %v", err)
		}
		return nil
	})
}

func routeFor(t *testing.T, host string) *unstructured.Unstructured {
	t.Helper()
	var rt *unstructured.Unstructured
	eventually(t, "HTTPRoute for "+host, func() error {
		var err error
		rt, err = routeOf(render.HostRouteName(host))
		return err
	})
	return rt
}

func gatewayZoneObj(name, domain string, ingress authv1.ZoneIngressMode) *authv1.Zone {
	return &authv1.Zone{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: authv1.ZoneSpec{Domain: domain, Ingress: ingress, TLS: authv1.ZoneTLS{Mode: authv1.ZoneTLSDefault},
			Gateway: &authv1.ZoneGateway{Namespace: egNamespace, Name: "eg"}}}
}

func createZone(t *testing.T, z *authv1.Zone) {
	t.Helper()
	if err := k8s.Create(ctx, z); err != nil {
		t.Fatal(err)
	}
	// Zones are mirrored into the admission ConfigMap other tests read: leave nothing behind
	t.Cleanup(func() { _ = k8s.Delete(ctx, z) })
}

func updateZone(t *testing.T, name string, f func(*authv1.Zone)) {
	t.Helper()
	eventually(t, "update zone "+name, func() error {
		z := &authv1.Zone{}
		if err := k8s.Get(ctx, client.ObjectKey{Name: name}, z); err != nil {
			return err
		}
		f(z)
		return k8s.Update(ctx, z)
	})
}

func condMessage(t *testing.T, s *authv1.Site, typ, want string) {
	t.Helper()
	if c := meta.FindStatusCondition(s.Status.Conditions, typ); c == nil || !strings.Contains(c.Message, want) {
		t.Fatalf("%s message %+v, want %q", typ, c, want)
	}
}

// foreignRoute is an HTTPRoute another team owns, attached to eg.
func foreignRoute(t *testing.T, ns, name string, hosts ...string) *unstructured.Unstructured {
	t.Helper()
	if err := k8s.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	var hs []any
	for _, h := range hosts {
		hs = append(hs, h)
	}
	rt := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{
		"parentRefs": []any{map[string]any{"name": "eg", "namespace": egNamespace}}, "hostnames": hs,
		"rules": []any{map[string]any{"backendRefs": []any{map[string]any{"name": "web", "port": int64(80)}}}}}}}
	rt.SetGroupVersionKind(render.HTTPRouteGVK)
	rt.SetNamespace(ns)
	rt.SetName(name)
	if err := k8s.Create(ctx, rt); err != nil {
		t.Fatal(err)
	}
	return rt
}

// TestGatewayZone: a Zone attached to eg gives each Site host one HTTPRoute
// (no Ingress with ingress none), RouteReady follows the Gateway's acceptance,
// and routes, listeners and Ingresses elsewhere take or shadow hosts.
func TestGatewayZone(t *testing.T) {
	createZone(t, gatewayZoneObj("gwz", "gw.example.com", authv1.ZoneIngressNone))
	z := zoneCond(t, "gwz", authv1.ConditionGatewayReady, metav1.ConditionTrue, "Programmed")
	if c := meta.FindStatusCondition(z.Status.Conditions, authv1.ConditionGatewayReady); !strings.Contains(c.Message, "envoy.elb.amazonaws.com, listener gw-https") {
		t.Fatalf("GatewayReady %q", c.Message)
	}
	zoneCond(t, "gwz", authv1.ConditionIngressReady, metav1.ConditionTrue, "NoIngress")
	zoneCond(t, "gwz", authv1.ConditionReady, metav1.ConditionTrue, "Ready")
	if _, err := ingressOf("zone-gwz"); !apierrors.IsNotFound(err) {
		t.Fatalf("ingress none: no wildcard Ingress: %v", err)
	}

	host := "alpha.gw.example.com"
	if err := k8s.Create(ctx, withHost(newSite("alpha-gw"), host)); err != nil {
		t.Fatal(err)
	}
	cond(t, "alpha-gw", authv1.ConditionRouteReady, metav1.ConditionFalse, "WaitingForGateway")
	cond(t, "alpha-gw", authv1.ConditionIngressReady, metav1.ConditionTrue, "NoIngress")
	rt := routeFor(t, host)
	if hs := routeHostnames(rt); len(hs) != 1 || hs[0] != host {
		t.Fatalf("hostnames %v", hs)
	}
	if o := rt.GetOwnerReferences(); len(o) != 1 || o[0].Name != "alpha-gw" || (o[0].Controller != nil && *o[0].Controller) {
		t.Fatalf("owners %+v", o)
	}
	if _, err := ingressOf(render.HostIngressName(host)); !apierrors.IsNotFound(err) {
		t.Fatalf("ingress none: no host Ingress: %v", err)
	}
	acceptRoute(t, rt.GetName())
	s := cond(t, "alpha-gw", authv1.ConditionRouteReady, metav1.ConditionTrue, "Accepted")
	condMessage(t, s, authv1.ConditionRouteReady, "accepted by Gateway envoy-gateway-system/eg")
	ackRules(t, "alpha-gw")
	s = cond(t, "alpha-gw", authv1.ConditionReady, metav1.ConditionTrue, "Ready")
	if !childOf(s, "HTTPRoute", rt.GetName()) {
		t.Fatalf("children %+v", s.Status.Children)
	}

	// a foreign route naming the host takes it: nothing created, until it goes
	legacy := foreignRoute(t, "legacy-gw", "web", "beta.gw.example.com")
	if err := k8s.Create(ctx, withHost(newSite("beta-gw"), "beta.gw.example.com")); err != nil {
		t.Fatal(err)
	}
	s = cond(t, "beta-gw", authv1.ConditionRouteReady, metav1.ConditionFalse, "HostTaken")
	condMessage(t, s, authv1.ConditionRouteReady, "HTTPRoute legacy-gw/web serves beta.gw.example.com")
	consistently(t, "no route for a taken host", 500*time.Millisecond, func() error {
		if _, err := routeOf(render.HostRouteName("beta.gw.example.com")); !apierrors.IsNotFound(err) {
			return fmt.Errorf("beta's route exists: %v", err)
		}
		return nil
	})
	if err := k8s.Delete(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	routeFor(t, "beta.gw.example.com")

	// an exact-hostname listener on eg (a ListenerSet elsewhere) wins the host: taken
	ls := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{
		"parentRef": map[string]any{"name": "eg", "namespace": egNamespace},
		"listeners": []any{map[string]any{"name": "https", "port": int64(443), "protocol": "HTTPS", "hostname": "gamma.gw.example.com",
			"tls": map[string]any{"certificateRefs": []any{map[string]any{"name": "gamma-tls"}}}}}}}}
	ls.SetGroupVersionKind(render.ListenerSetGVK)
	ls.SetNamespace("legacy-gw")
	ls.SetName("gamma")
	if err := k8s.Create(ctx, ls); err != nil {
		t.Fatal(err)
	}
	if err := k8s.Create(ctx, withHost(newSite("gamma-gw"), "gamma.gw.example.com")); err != nil {
		t.Fatal(err)
	}
	s = cond(t, "gamma-gw", authv1.ConditionRouteReady, metav1.ConditionFalse, "HostTaken")
	condMessage(t, s, authv1.ConditionRouteReady, "ListenerSet legacy-gw/gamma (listener https) serves gamma.gw.example.com")

	// a foreign Ingress naming the host takes it too (a DNS move would hijack it)
	foreignIngress(t, "legacy-gw", "delta", "delta.gw.example.com")
	if err := k8s.Create(ctx, withHost(newSite("delta-gw"), "delta.gw.example.com")); err != nil {
		t.Fatal(err)
	}
	cond(t, "delta-gw", authv1.ConditionRouteReady, metav1.ConditionFalse, "HostTaken")

	// a foreign wildcard route only shadows (the exact hostname wins): a warning
	wild := foreignRoute(t, "legacy-gw", "wild", "*.gw.example.com")
	s = cond(t, "alpha-gw", authv1.ConditionHostShadowsWildcard, metav1.ConditionTrue, "WildcardShadowed")
	condMessage(t, s, authv1.ConditionHostShadowsWildcard, "HTTPRoute legacy-gw/wild serves *.gw.example.com; the gateway routes alpha.gw.example.com to this Site")
	cond(t, "alpha-gw", authv1.ConditionRouteReady, metav1.ConditionTrue, "Accepted")
	if err := k8s.Delete(ctx, wild); err != nil {
		t.Fatal(err)
	}
	cond(t, "alpha-gw", authv1.ConditionHostShadowsWildcard, metav1.ConditionFalse, "NoWildcard")

	// the last Site on the host goes: so does its route
	for _, n := range []string{"alpha-gw", "beta-gw", "gamma-gw", "delta-gw"} {
		if err := k8s.Delete(ctx, getSite(t, n)); err != nil {
			t.Fatal(err)
		}
	}
	routeGone(t, rt.GetName())
	routeGone(t, render.HostRouteName("beta.gw.example.com"))
}

func childOf(s *authv1.Site, kind, name string) bool {
	for _, c := range s.Status.Children {
		if c.Kind == kind && c.Name == name {
			return true
		}
	}
	return false
}

// TestGatewayZoneRefusals: a Gateway outside --gateways, a Gateway without a
// listener for the zone, and a zone without any entry point.
func TestGatewayZoneRefusals(t *testing.T) {
	other := gatewayZoneObj("gw-other", "other.example.com", authv1.ZoneIngressNone)
	other.Spec.Gateway.Name = "internal"
	createZone(t, other)
	zoneCond(t, "gw-other", authv1.ConditionValidated, metav1.ConditionFalse, "GatewayNotAllowed")
	zoneCond(t, "gw-other", authv1.ConditionReady, metav1.ConditionFalse, "GatewayNotAllowed")
	if err := k8s.Create(ctx, withHost(newSite("other-gw"), "a.other.example.com")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = k8s.Delete(ctx, &authv1.Site{ObjectMeta: metav1.ObjectMeta{Name: "other-gw", Namespace: "auth"}})
	})
	s := cond(t, "other-gw", authv1.ConditionRouteReady, metav1.ConditionFalse, "GatewayNotUsable")
	condMessage(t, s, authv1.ConditionRouteReady, "gateway envoy-gateway-system/internal is not allowed")
	if _, err := routeOf(render.HostRouteName("a.other.example.com")); !apierrors.IsNotFound(err) {
		t.Fatalf("no route to a Gateway outside --gateways: %v", err)
	}

	createZone(t, gatewayZoneObj("gw-nocover", "nocover.example.com", authv1.ZoneIngressNone))
	z := zoneCond(t, "gw-nocover", authv1.ConditionGatewayReady, metav1.ConditionFalse, "ListenerDoesNotCover")
	if c := meta.FindStatusCondition(z.Status.Conditions, authv1.ConditionGatewayReady); !strings.Contains(c.Message, "no HTTPS listener for *.nocover.example.com") {
		t.Fatalf("message %q", c.Message)
	}
	zoneCond(t, "gw-nocover", authv1.ConditionReady, metav1.ConditionFalse, "ListenerDoesNotCover")

	bad := &authv1.Zone{ObjectMeta: metav1.ObjectMeta{Name: "gw-none"},
		Spec: authv1.ZoneSpec{Domain: "none.example.com", Ingress: authv1.ZoneIngressNone}}
	if err := k8s.Create(ctx, bad); err == nil || !strings.Contains(err.Error(), "ingress none needs a gateway") {
		t.Fatalf("a zone without an entry point was accepted: %v", err)
	}
}

// TestZoneMovesFromIngressToGateway is the per-zone migration: per-site
// Ingresses → Ingresses + routes (DNS still on nginx) → routes only, then the
// rollback. The Sites' Rules are never touched (no event at all), and every step
// keeps each host served by at least one entry point.
func TestZoneMovesFromIngressToGateway(t *testing.T) {
	z := gatewayZoneObj("mv", "mv.example.com", authv1.ZoneIngressPerSite)
	z.Spec.Gateway = nil
	createZone(t, z)
	zoneCond(t, "mv", authv1.ConditionReady, metav1.ConditionTrue, "Ready")
	zoneCond(t, "mv", authv1.ConditionGatewayReady, metav1.ConditionTrue, "NoGateway")
	hosts := map[string]string{"mv-a": "a.mv.example.com", "mv-b": "b.mv.example.com"}
	for name, host := range hosts {
		if err := k8s.Create(ctx, withHost(newSite(name), host)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = k8s.Delete(ctx, &authv1.Site{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth"}})
		})
	}
	for name, host := range hosts {
		twoRules(t, name)
		admit(t, render.HostIngressName(host))
		ackRules(t, name)
		cond(t, name, authv1.ConditionRouteReady, metav1.ConditionTrue, "NoGateway")
		cond(t, name, authv1.ConditionReady, metav1.ConditionTrue, "Ready")
	}
	before := map[string]map[string]string{}
	for name := range hosts {
		before[name] = map[string]string{}
		for _, r := range rulesOf(t, name) {
			before[name][r.Name] = r.ResourceVersion
		}
	}

	// 1. add the gateway: every host gets its route, the Ingresses stay (DNS still on nginx)
	updateZone(t, "mv", func(z *authv1.Zone) { z.Spec.Gateway = &authv1.ZoneGateway{Namespace: egNamespace, Name: "eg"} })
	zc := zoneCond(t, "mv", authv1.ConditionGatewayReady, metav1.ConditionTrue, "Programmed")
	if c := meta.FindStatusCondition(zc.Status.Conditions, authv1.ConditionReady); c == nil || !strings.Contains(c.Message, "migration") {
		t.Fatalf("zone Ready %+v", c)
	}
	for name, host := range hosts {
		acceptRoute(t, routeFor(t, host).GetName())
		cond(t, name, authv1.ConditionRouteReady, metav1.ConditionTrue, "Accepted")
		cond(t, name, authv1.ConditionIngressReady, metav1.ConditionTrue, "Admitted")
		cond(t, name, authv1.ConditionReady, metav1.ConditionTrue, "Ready")
		if _, err := ingressOf(render.HostIngressName(host)); err != nil {
			t.Fatalf("the Ingress of %s must stay until DNS moved: %v", host, err)
		}
	}

	// 3. (DNS moved) ingress none: the Ingresses go, the routes stay
	updateZone(t, "mv", func(z *authv1.Zone) { z.Spec.Ingress = authv1.ZoneIngressNone })
	zoneCond(t, "mv", authv1.ConditionIngressReady, metav1.ConditionTrue, "NoIngress")
	for name, host := range hosts {
		gone(t, render.HostIngressName(host))
		cond(t, name, authv1.ConditionIngressReady, metav1.ConditionTrue, "NoIngress")
		cond(t, name, authv1.ConditionReady, metav1.ConditionTrue, "Ready")
		if _, err := routeOf(render.HostRouteName(host)); err != nil {
			t.Fatal(err)
		}
	}

	// rollback: the Ingresses come back first, then the gateway can go
	updateZone(t, "mv", func(z *authv1.Zone) { z.Spec.Ingress = authv1.ZoneIngressPerSite })
	for name, host := range hosts {
		admit(t, render.HostIngressName(host))
		cond(t, name, authv1.ConditionIngressReady, metav1.ConditionTrue, "Admitted")
	}
	updateZone(t, "mv", func(z *authv1.Zone) { z.Spec.Gateway = nil })
	for name, host := range hosts {
		routeGone(t, render.HostRouteName(host))
		cond(t, name, authv1.ConditionRouteReady, metav1.ConditionTrue, "NoGateway")
		cond(t, name, authv1.ConditionReady, metav1.ConditionTrue, "Ready")
	}

	// the Rules were never written: same names, same resourceVersions, still acknowledged
	for name := range hosts {
		rules := rulesOf(t, name)
		if len(rules) != len(before[name]) {
			t.Fatalf("%s: rules %d, want %d", name, len(rules), len(before[name]))
		}
		for _, r := range rules {
			if before[name][r.Name] != r.ResourceVersion {
				t.Fatalf("rule %s was written during the migration (rv %s → %s)", r.Name, before[name][r.Name], r.ResourceVersion)
			}
		}
	}
}

// TestZoneOwnListener: a Zone with its own certificate (tls secret) brings a
// ListenerSet to eg and its routes attach to it; GatewayReady waits for EG to
// accept and program it (allowedListeners).
func TestZoneOwnListener(t *testing.T) {
	z := gatewayZoneObj("own", "own.example.com", authv1.ZoneIngressNone)
	z.Spec.TLS = authv1.ZoneTLS{Mode: authv1.ZoneTLSSecret, SecretName: "own-wildcard"}
	createZone(t, z)
	zoneCond(t, "own", authv1.ConditionGatewayReady, metav1.ConditionFalse, "Pending")
	ls := &unstructured.Unstructured{}
	ls.SetGroupVersionKind(render.ListenerSetGVK)
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "zone-own"}, ls); err != nil {
		t.Fatal(err)
	}
	if l, _, _ := unstructured.NestedSlice(ls.Object, "spec", "listeners"); len(l) != 1 || l[0].(map[string]any)["hostname"] != "*.own.example.com" {
		t.Fatalf("listeners %v", l)
	}
	ls.Object["status"] = map[string]any{"conditions": condList("Accepted", "Programmed")}
	if err := k8s.Status().Update(ctx, ls); err != nil {
		t.Fatal(err)
	}
	zc := zoneCond(t, "own", authv1.ConditionGatewayReady, metav1.ConditionTrue, "Programmed")
	if c := meta.FindStatusCondition(zc.Status.Conditions, authv1.ConditionGatewayReady); !strings.Contains(c.Message, "ListenerSet zone-own") {
		t.Fatalf("message %q", c.Message)
	}
	if err := k8s.Create(ctx, withHost(newSite("own-a"), "a.own.example.com")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = k8s.Delete(ctx, &authv1.Site{ObjectMeta: metav1.ObjectMeta{Name: "own-a", Namespace: "auth"}})
	})
	rt := routeFor(t, "a.own.example.com")
	refs, _, _ := unstructured.NestedSlice(rt.Object, "spec", "parentRefs")
	if p := refs[0].(map[string]any); p["kind"] != "ListenerSet" || p["name"] != "zone-own" || p["sectionName"] != "https" {
		t.Fatalf("parentRef %v", p)
	}

	// back to the Gateway's certificate: the ListenerSet goes
	updateZone(t, "own", func(z *authv1.Zone) { z.Spec.TLS = authv1.ZoneTLS{Mode: authv1.ZoneTLSDefault} })
	eventually(t, "zone-own ListenerSet deleted", func() error {
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "zone-own"}, ls); !apierrors.IsNotFound(err) {
			return fmt.Errorf("still there: %v", err)
		}
		return nil
	})
}
