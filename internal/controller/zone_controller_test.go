package controller

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/render"
)

func zoneCond(t *testing.T, name, typ string, status metav1.ConditionStatus, reason string) *authv1.Zone {
	t.Helper()
	z := &authv1.Zone{}
	eventually(t, fmt.Sprintf("zone %s %s=%s/%s", name, typ, status, reason), func() error {
		if err := k8s.Get(ctx, client.ObjectKey{Name: name}, z); err != nil {
			return err
		}
		c := meta.FindStatusCondition(z.Status.Conditions, typ)
		if c == nil || c.ObservedGeneration != z.Generation || c.Status != status || c.Reason != reason {
			return fmt.Errorf("conditions %+v", z.Status.Conditions)
		}
		return nil
	})
	return z
}

func mirrored(t *testing.T, want string) {
	t.Helper()
	eventually(t, "zones mirrored as "+want, func() error {
		cm := &corev1.ConfigMap{}
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "site-operator-zones"}, cm); err != nil {
			return err
		}
		if got := cm.Data[ZonesDomainsKey]; got != want {
			return fmt.Errorf("domains %q", got)
		}
		return nil
	})
}

func TestDevZoneHasOneWildcardIngress(t *testing.T) {
	z := zoneCond(t, "dev", authv1.ConditionReady, metav1.ConditionTrue, "Ready")
	ing, err := ingressOf("zone-dev")
	if err != nil {
		t.Fatal(err)
	}
	ownedBy(t, ing, z)
	if len(ing.Spec.Rules) != 1 || ing.Spec.Rules[0].Host != "*.dev.example.com" || len(ing.Spec.TLS) != 0 {
		t.Fatalf("bad zone ingress %+v", ing.Spec)
	}
	if b := ing.Spec.Rules[0].HTTP.Paths[0].Backend.Service; b.Name != "auth-oathkeeper-proxy" {
		t.Fatalf("backend %+v", b)
	}
	mirrored(t, "dev.example.com")
}

func TestIssuerZoneCertificateAndSiteReadiness(t *testing.T) {
	z := &authv1.Zone{ObjectMeta: metav1.ObjectMeta{Name: "sandbox"},
		Spec: authv1.ZoneSpec{Domain: "authdev.dev.example.com", TLS: authv1.ZoneTLS{Mode: authv1.ZoneTLSIssuer}}}
	if err := k8s.Create(ctx, z); err != nil {
		t.Fatal(err)
	}
	z = zoneCond(t, "sandbox", authv1.ConditionCertificateReady, metav1.ConditionFalse, "Pending")
	mirrored(t, "authdev.dev.example.com,dev.example.com")
	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(render.CertificateGVK)
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "zone-sandbox"}, cert); err != nil {
		t.Fatal(err)
	}
	ownedBy(t, cert, z)
	if dns, _, _ := unstructured.NestedStringSlice(cert.Object, "spec", "dnsNames"); len(dns) != 1 || dns[0] != "*.authdev.dev.example.com" {
		t.Fatalf("dnsNames %v", dns)
	}
	ing, err := ingressOf("zone-sandbox")
	if err != nil {
		t.Fatal(err)
	}
	if ing.Spec.TLS[0].SecretName != "zone-sandbox-tls" {
		t.Fatalf("tls %+v", ing.Spec.TLS)
	}

	// a Site in the zone is valid but not reachable until the zone is ready
	s := newSite("ledger")
	s.Spec.Hosts = []string{"ledger.authdev.dev.example.com"}
	for i := range s.Spec.Gates {
		s.Spec.Gates[i].Match.URL = "https://ledger.authdev.dev.example.com/<.*>"
	}
	s.Spec.Gates = s.Spec.Gates[1:]
	if err := k8s.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	cond(t, "ledger", authv1.ConditionIngressReady, metav1.ConditionFalse, "ZoneNotReady")

	admitIngress(t, "zone-sandbox")
	_ = unstructured.SetNestedSlice(cert.Object, []any{map[string]any{"type": "Ready", "status": "True", "reason": "Ready"}}, "status", "conditions")
	if err := k8s.Status().Update(ctx, cert); err != nil {
		t.Fatal(err)
	}
	zoneCond(t, "sandbox", authv1.ConditionReady, metav1.ConditionTrue, "Ready")
	cond(t, "ledger", authv1.ConditionIngressReady, metav1.ConditionTrue, "Zone")
	cond(t, "ledger", authv1.ConditionCertificateReady, metav1.ConditionTrue, "Zone")

	if err := k8s.Delete(ctx, z); err != nil {
		t.Fatal(err)
	}
	mirrored(t, "dev.example.com")
	cond(t, "ledger", authv1.ConditionValidated, metav1.ConditionFalse, "HostNotInZone")
}

func TestDuplicateZoneDomainIsRefused(t *testing.T) {
	z := &authv1.Zone{ObjectMeta: metav1.ObjectMeta{Name: "dev-copy"}, Spec: authv1.ZoneSpec{Domain: "dev.example.com"}}
	if err := k8s.Create(ctx, z); err != nil {
		t.Fatal(err)
	}
	zoneCond(t, "dev-copy", authv1.ConditionValidated, metav1.ConditionFalse, "DomainTaken")
	if _, err := ingressOf("zone-dev-copy"); !apierrors.IsNotFound(err) {
		t.Fatalf("refused zone rendered an Ingress: %v", err)
	}
	_ = k8s.Delete(ctx, z)
}
