package controller

import (
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
)

// foreignIngress is an Ingress another team owns, in another namespace.
func foreignIngress(t *testing.T, ns, name, host string) *networkingv1.Ingress {
	t.Helper()
	if err := k8s.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	pt := networkingv1.PathTypePrefix
	ing := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{Host: host, IngressRuleValue: networkingv1.IngressRuleValue{
			HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{Path: "/", PathType: &pt,
				Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "web", Port: networkingv1.ServiceBackendPort{Number: 80}}}}}}}}}}}
	if err := k8s.Create(ctx, ing); err != nil {
		t.Fatal(err)
	}
	return ing
}

func ingressCond(t *testing.T, site string, status metav1.ConditionStatus, reason, msg string) {
	t.Helper()
	s := cond(t, site, authv1.ConditionIngressReady, status, reason)
	if c := meta.FindStatusCondition(s.Status.Conditions, authv1.ConditionIngressReady); !strings.Contains(c.Message, msg) {
		t.Fatalf("message %q, want %q", c.Message, msg)
	}
}

func admit(t *testing.T, name string) {
	t.Helper()
	eventually(t, "admit "+name, func() error {
		ing, err := ingressOf(name)
		if err != nil {
			return err
		}
		ing.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{{Hostname: "lb.example"}}
		return k8s.Status().Update(ctx, ing)
	})
}

func gone(t *testing.T, name string) {
	t.Helper()
	eventually(t, name+" deleted", func() error {
		if _, err := ingressOf(name); !apierrors.IsNotFound(err) {
			return fmt.Errorf("still there: %v", err)
		}
		return nil
	})
}

// TestPerSiteZone: a Zone on a domain other Ingresses already use gets no
// wildcard; each Site gets an exact-host Ingress unless the host is taken
// anywhere in the cluster; switching the mode is handled both ways.
func TestPerSiteZone(t *testing.T) {
	zone := &authv1.Zone{ObjectMeta: metav1.ObjectMeta{Name: "shared"},
		Spec: authv1.ZoneSpec{Domain: "shared.example.com", Ingress: authv1.ZoneIngressPerSite, TLS: authv1.ZoneTLS{Mode: authv1.ZoneTLSDefault}}}
	if err := k8s.Create(ctx, zone); err != nil {
		t.Fatal(err)
	}
	zoneCond(t, "shared", authv1.ConditionIngressReady, metav1.ConditionTrue, "PerSite")
	zoneCond(t, "shared", authv1.ConditionReady, metav1.ConditionTrue, "Ready")
	if _, err := ingressOf("zone-shared"); !apierrors.IsNotFound(err) {
		t.Fatalf("a per-site Zone has no wildcard Ingress: %v", err)
	}

	// a Site gets its own exact-host Ingress to the gateway
	if err := k8s.Create(ctx, withHost(newSite("alpha"), "alpha.shared.example.com")); err != nil {
		t.Fatal(err)
	}
	ingressCond(t, "alpha", metav1.ConditionFalse, "WaitingForAddress", "")
	ing, err := ingressOf("site-alpha")
	if err != nil {
		t.Fatal(err)
	}
	ownedBy(t, ing, getSite(t, "alpha"))
	r := ing.Spec.Rules
	if len(r) != 1 || r[0].Host != "alpha.shared.example.com" || r[0].HTTP.Paths[0].Backend.Service.Name != cfg.GatewayService || len(ing.Spec.TLS) != 0 {
		t.Fatalf("site Ingress %+v", ing.Spec)
	}
	admit(t, "site-alpha")
	ingressCond(t, "alpha", metav1.ConditionTrue, "Admitted", "lb.example")
	cond(t, "alpha", authv1.ConditionCertificateReady, metav1.ConditionTrue, "Zone")

	// the host is served by an Ingress in another namespace: nothing created
	legacy := foreignIngress(t, "legacy", "web", "beta.shared.example.com")
	if err := k8s.Create(ctx, withHost(newSite("beta"), "beta.shared.example.com")); err != nil {
		t.Fatal(err)
	}
	ingressCond(t, "beta", metav1.ConditionFalse, "HostTaken", "legacy/web serves beta.shared.example.com")
	ackRules(t, "beta")
	cond(t, "beta", authv1.ConditionReady, metav1.ConditionFalse, "HostTaken")
	consistently(t, "no Ingress for a taken host", 500*time.Millisecond, func() error {
		if _, err := ingressOf("site-beta"); !apierrors.IsNotFound(err) {
			return fmt.Errorf("site-beta exists: %v", err)
		}
		return nil
	})
	// the other Ingress goes away: the Site's Ingress is created (Ingress watch, no Site change)
	if err := k8s.Delete(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	ingressCond(t, "beta", metav1.ConditionFalse, "WaitingForAddress", "")

	// a wildcard elsewhere (e.g. loki/loki-alloy *.dev.example.com /collect):
	// not a collision, our exact host overrides it for that host → warning only
	wild := foreignIngress(t, "legacy", "wild", "*.shared.example.com")
	s := cond(t, "alpha", authv1.ConditionHostShadowsWildcard, metav1.ConditionTrue, "WildcardShadowed")
	if c := meta.FindStatusCondition(s.Status.Conditions, authv1.ConditionHostShadowsWildcard); c.Message != "legacy/wild serves *.shared.example.com; nginx routes alpha.shared.example.com to this Site (paths of that Ingress, e.g. /, are not served on this host)" {
		t.Fatalf("message %q", c.Message)
	}
	ingressCond(t, "alpha", metav1.ConditionTrue, "Admitted", "") // IngressReady stays True
	if err := k8s.Create(ctx, withHost(newSite("gamma"), "gamma.shared.example.com")); err != nil {
		t.Fatal(err)
	}
	ingressCond(t, "gamma", metav1.ConditionFalse, "WaitingForAddress", "") // created despite the wildcard
	cond(t, "gamma", authv1.ConditionHostShadowsWildcard, metav1.ConditionTrue, "WildcardShadowed")
	if err := k8s.Delete(ctx, wild); err != nil {
		t.Fatal(err)
	}
	cond(t, "alpha", authv1.ConditionHostShadowsWildcard, metav1.ConditionFalse, "NoWildcard")

	// switch to wildcard: the Zone's wildcard serves, the per-site Ingresses go
	setZoneMode(t, "shared", authv1.ZoneIngressWildcard)
	gone(t, "site-alpha")
	gone(t, "site-beta")
	gone(t, "site-gamma")
	if _, err := ingressOf("zone-shared"); err != nil {
		t.Fatalf("wildcard Ingress: %v", err)
	}
	admit(t, "zone-shared")
	ingressCond(t, "alpha", metav1.ConditionTrue, "Zone", "served by zone shared")

	// and back: the wildcard goes, each Site gets its Ingress again
	setZoneMode(t, "shared", authv1.ZoneIngressPerSite)
	gone(t, "zone-shared")
	ingressCond(t, "alpha", metav1.ConditionFalse, "WaitingForAddress", "")
	if _, err := ingressOf("site-beta"); err != nil {
		t.Fatal(err)
	}
}

// TestPerSiteZoneTLSSecret: a per-site Ingress uses its Zone's TLS Secret.
func TestPerSiteZoneTLSSecret(t *testing.T) {
	zone := &authv1.Zone{ObjectMeta: metav1.ObjectMeta{Name: "secured"},
		Spec: authv1.ZoneSpec{Domain: "secured.example.com", Ingress: authv1.ZoneIngressPerSite,
			TLS: authv1.ZoneTLS{Mode: authv1.ZoneTLSSecret, SecretName: "secured-wildcard"}}}
	if err := k8s.Create(ctx, zone); err != nil {
		t.Fatal(err)
	}
	zoneCond(t, "secured", authv1.ConditionReady, metav1.ConditionTrue, "Ready")
	eventually(t, "zone secret mirrored", func() error {
		cm := &corev1.ConfigMap{}
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "site-operator-zones"}, cm); err != nil {
			return err
		}
		if !strings.Contains(cm.Data[ZonesSecretsKey], "secured-wildcard") {
			return fmt.Errorf("secrets %q", cm.Data[ZonesSecretsKey])
		}
		return nil
	})
	if err := k8s.Create(ctx, withHost(newSite("safe"), "safe.secured.example.com")); err != nil {
		t.Fatal(err)
	}
	ingressCond(t, "safe", metav1.ConditionFalse, "WaitingForAddress", "")
	ing, _ := ingressOf("site-safe")
	if len(ing.Spec.TLS) != 1 || ing.Spec.TLS[0].SecretName != "secured-wildcard" || ing.Spec.TLS[0].Hosts[0] != "safe.secured.example.com" {
		t.Fatalf("tls %+v", ing.Spec.TLS)
	}
}

func setZoneMode(t *testing.T, name string, mode authv1.ZoneIngressMode) {
	t.Helper()
	eventually(t, "set zone mode", func() error {
		z := &authv1.Zone{}
		if err := k8s.Get(ctx, client.ObjectKey{Name: name}, z); err != nil {
			return err
		}
		z.Spec.Ingress = mode
		return k8s.Update(ctx, z)
	})
}

// withHost moves a test Site to another host (patterns follow).
func withHost(s *authv1.Site, host string) *authv1.Site {
	old := s.Spec.Hosts[0]
	s.Spec.Hosts = []string{host}
	for i := range s.Spec.Gates {
		s.Spec.Gates[i].Match.URL = strings.ReplaceAll(s.Spec.Gates[i].Match.URL, old, host)
	}
	return s
}
