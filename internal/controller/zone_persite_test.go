package controller

import (
	"fmt"
	"slices"
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
	"github.com/w6d-io/site-operator/internal/render"
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

	// a Site's host gets an exact-host Ingress to the gateway
	if err := k8s.Create(ctx, withHost(newSite("alpha"), "alpha.shared.example.com")); err != nil {
		t.Fatal(err)
	}
	ingressCond(t, "alpha", metav1.ConditionFalse, "WaitingForAddress", "")
	ing, err := ingressOf(hostIng("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	owners(t, ing, "alpha")
	if ing.Annotations[render.HostAnnotation] != "alpha.shared.example.com" {
		t.Fatalf("host annotation %v", ing.Annotations)
	}
	r := ing.Spec.Rules
	if len(r) != 1 || r[0].Host != "alpha.shared.example.com" || r[0].HTTP.Paths[0].Backend.Service.Name != cfg.GatewayService || len(ing.Spec.TLS) != 0 {
		t.Fatalf("site Ingress %+v", ing.Spec)
	}
	admit(t, hostIng("alpha"))
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
		if _, err := ingressOf(hostIng("beta")); !apierrors.IsNotFound(err) {
			return fmt.Errorf("beta's host Ingress exists: %v", err)
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
	gone(t, hostIng("alpha"))
	gone(t, hostIng("beta"))
	gone(t, hostIng("gamma"))
	if _, err := ingressOf("zone-shared"); err != nil {
		t.Fatalf("wildcard Ingress: %v", err)
	}
	admit(t, "zone-shared")
	ingressCond(t, "alpha", metav1.ConditionTrue, "Zone", "served by zone shared")

	// and back: the wildcard goes, each Site gets its Ingress again
	setZoneMode(t, "shared", authv1.ZoneIngressPerSite)
	gone(t, "zone-shared")
	ingressCond(t, "alpha", metav1.ConditionFalse, "WaitingForAddress", "")
	eventually(t, "beta's host Ingress is back", func() error {
		_, err := ingressOf(hostIng("beta"))
		return err
	})
}

// hostIng is the host Ingress name of <name>.shared.example.com.
func hostIng(name string) string { return render.HostIngressName(name + ".shared.example.com") }

// owners checks an Ingress is owned by exactly these Sites, none of them the controller.
func owners(t *testing.T, ing *networkingv1.Ingress, sites ...string) {
	t.Helper()
	var got []string
	for _, o := range ing.OwnerReferences {
		if o.Kind != "Site" || (o.Controller != nil && *o.Controller) {
			t.Fatalf("owner %+v: Sites only, no controller", o)
		}
		got = append(got, o.Name)
	}
	slices.Sort(got)
	if fmt.Sprint(got) != fmt.Sprint(sites) {
		t.Fatalf("owners %v, want %v", got, sites)
	}
}

// TestSitesShareHostIngress: two Sites on one host (route prefixes, e.g.
// wallets-api /wallets/api and wallets-treasury /wallets/treasury) share its
// Ingress; both are Ready, and it goes only with the last one.
func TestSitesShareHostIngress(t *testing.T) {
	zone := &authv1.Zone{ObjectMeta: metav1.ObjectMeta{Name: "sharedhost"},
		Spec: authv1.ZoneSpec{Domain: "sh.example.com", Ingress: authv1.ZoneIngressPerSite, TLS: authv1.ZoneTLS{Mode: authv1.ZoneTLSDefault}}}
	if err := k8s.Create(ctx, zone); err != nil {
		t.Fatal(err)
	}
	zoneCond(t, "sharedhost", authv1.ConditionReady, metav1.ConditionTrue, "Ready")
	host := "superadmin.sh.example.com"
	name := render.HostIngressName(host)
	prefixed := func(site, prefix string) *authv1.Site {
		s := withHost(newSite(site), host)
		s.Spec.Gates[0].Match.URL = "<https?>://" + host + "/" + prefix + "/<(health|docs)(/.*)?>"
		s.Spec.Gates[1].Match.URL = "<https?>://" + host + "/" + prefix + "/<(?!(health|docs)(/.*)?$).*>"
		return s
	}
	for _, s := range []*authv1.Site{prefixed("wallets-api", "wallets/api"), prefixed("wallets-treasury", "wallets/treasury")} {
		if err := k8s.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	ingressCond(t, "wallets-treasury", metav1.ConditionFalse, "WaitingForAddress", "")
	eventually(t, "both Sites own the host Ingress", func() error {
		ing, err := ingressOf(name)
		if err != nil {
			return err
		}
		if len(ing.OwnerReferences) != 2 {
			return fmt.Errorf("owners %v", ing.OwnerReferences)
		}
		return nil
	})
	ing, _ := ingressOf(name)
	owners(t, ing, "wallets-api", "wallets-treasury")
	admit(t, name)
	for _, s := range []string{"wallets-api", "wallets-treasury"} {
		ingressCond(t, s, metav1.ConditionTrue, "Admitted", "")
		ackRules(t, s)
		cond(t, s, authv1.ConditionReady, metav1.ConditionTrue, "Ready")
	}

	// deleting one keeps the Ingress for the other
	if err := k8s.Delete(ctx, getSite(t, "wallets-api")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "wallets-api released", func() error {
		ing, err := ingressOf(name)
		if err != nil {
			return err
		}
		if len(ing.OwnerReferences) != 1 {
			return fmt.Errorf("owners %v", ing.OwnerReferences)
		}
		return nil
	})
	ing, _ = ingressOf(name)
	owners(t, ing, "wallets-treasury")
	consistently(t, "treasury still served", 500*time.Millisecond, func() error {
		if _, err := ingressOf(name); err != nil {
			return err
		}
		return nil
	})
	cond(t, "wallets-treasury", authv1.ConditionReady, metav1.ConditionTrue, "Ready")

	// the last Site goes: so does the host Ingress
	if err := k8s.Delete(ctx, getSite(t, "wallets-treasury")); err != nil {
		t.Fatal(err)
	}
	gone(t, name)
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
	ing, _ := ingressOf(render.HostIngressName("safe.secured.example.com"))
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
