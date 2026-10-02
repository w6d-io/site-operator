// Package zonescope runs the operator with --zones against its own envtest API
// server: the controller suite's operator owns every Zone, so a Zone untouched
// by a scoped operator can only be observed without it.
package zonescope

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
	"github.com/w6d-io/site-operator/internal/controller"
	"github.com/w6d-io/site-operator/internal/render"
	"github.com/w6d-io/site-operator/internal/testenv"
	"github.com/w6d-io/site-operator/internal/validate"
)

var (
	ctx = context.Background()
	k8s client.Client
)

func TestMain(m *testing.M) {
	env := testenv.New()
	if env == nil {
		fmt.Println("envtest binaries not found (run: setup-envtest use " + testenv.K8sVersion + "); skipping zone scope tests")
		os.Exit(0)
	}
	rc, err := env.Start()
	if err != nil {
		panic(err)
	}
	cfg := config.Default()
	cfg.Zones = []string{"owned"} // --zones=owned

	mgr, err := ctrl.NewManager(rc, ctrl.Options{Scheme: testenv.Scheme(), Metrics: metricsserver.Options{BindAddress: "0"}})
	if err != nil {
		panic(err)
	}
	rec := mgr.GetEventRecorderFor("site-operator")
	s := &controller.SiteReconciler{Client: mgr.GetClient(), Config: cfg, Validator: &validate.Mock{}, Recorder: rec}
	if err := s.SetupWithManager(mgr); err != nil {
		panic(err)
	}
	z := &controller.ZoneReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Config: cfg, Recorder: rec}
	if err := z.SetupWithManager(mgr); err != nil {
		panic(err)
	}
	mctx, cancel := context.WithCancel(ctx)
	go func() {
		if err := mgr.Start(mctx); err != nil {
			panic(err)
		}
	}()
	if k8s, err = client.New(rc, client.Options{Scheme: testenv.Scheme()}); err != nil {
		panic(err)
	}
	if err := k8s.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "auth"}}); err != nil {
		panic(err)
	}
	if err := testenv.ApplyFiles(ctx, k8s, filepath.Join(testenv.Root(), "config", "rbac"), "zones_configmap.yaml"); err != nil {
		panic(err)
	}
	// both Zones bring a Certificate, so a foreign one reconciled by mistake would show a child
	for _, name := range []string{"owned", "foreign"} {
		zone := &authv1.Zone{ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: authv1.ZoneSpec{Domain: name + ".example.com", TLS: authv1.ZoneTLS{Mode: authv1.ZoneTLSIssuer}}}
		if err := k8s.Create(ctx, zone); err != nil {
			panic(err)
		}
	}
	code := m.Run()
	cancel()
	_ = env.Stop()
	os.Exit(code)
}

func eventually(t *testing.T, what string, f func() error) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		if err = f(); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s: %v", what, err)
}

func consistently(t *testing.T, what string, d time.Duration, f func() error) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if err := f(); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func absent(obj client.Object, name string) error {
	err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: name}, obj)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("%s exists", name)
	}
	return err
}

func certificate() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(render.CertificateGVK)
	return u
}

func TestOnlyTheListedZoneIsReconciled(t *testing.T) {
	eventually(t, "owned zone validated, with its Ingress and Certificate", func() error {
		z := &authv1.Zone{}
		if err := k8s.Get(ctx, client.ObjectKey{Name: "owned"}, z); err != nil {
			return err
		}
		if c := meta.FindStatusCondition(z.Status.Conditions, authv1.ConditionValidated); c == nil || c.Status != metav1.ConditionTrue {
			return fmt.Errorf("conditions %+v", z.Status.Conditions)
		}
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "zone-owned"}, &networkingv1.Ingress{}); err != nil {
			return err
		}
		return k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "zone-owned"}, certificate())
	})
	consistently(t, "foreign zone untouched", 2*time.Second, func() error {
		z := &authv1.Zone{}
		if err := k8s.Get(ctx, client.ObjectKey{Name: "foreign"}, z); err != nil {
			return err
		}
		if len(z.Status.Conditions) != 0 || z.Status.ObservedGeneration != 0 {
			return fmt.Errorf("foreign zone status written: %+v", z.Status)
		}
		if err := absent(&networkingv1.Ingress{}, "zone-foreign"); err != nil {
			return err
		}
		return absent(certificate(), "zone-foreign")
	})
	cm := &corev1.ConfigMap{}
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "site-operator-zones"}, cm); err != nil {
		t.Fatal(err)
	}
	if got := cm.Data[controller.ZonesDomainsKey]; got != "owned.example.com" {
		t.Fatalf("mirror must list the owned zone only, got %q", got)
	}
}

func newSite(name, host string) *authv1.Site {
	return &authv1.Site{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth"},
		Spec: authv1.SiteSpec{
			Hosts:    []string{host},
			Upstream: authv1.Upstream{Service: name, Namespace: name, Port: 8080},
			Gates: []authv1.Gate{{
				Name:           "main",
				Match:          authv1.Match{URL: "<https?>://" + host + "/<.*>", Methods: []string{"GET"}},
				Authenticators: []authv1.Handler{{Handler: "noop"}},
				Authorizer:     authv1.Handler{Handler: "allow"},
				Mutators:       []authv1.Handler{{Handler: "noop"}},
			}},
		},
	}
}

func validated(t *testing.T, name string, status metav1.ConditionStatus, reason string) {
	t.Helper()
	eventually(t, fmt.Sprintf("site %s Validated=%s/%s", name, status, reason), func() error {
		s := &authv1.Site{}
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: name}, s); err != nil {
			return err
		}
		c := meta.FindStatusCondition(s.Status.Conditions, authv1.ConditionValidated)
		if c == nil || c.Status != status || c.Reason != reason {
			return fmt.Errorf("conditions %+v", s.Status.Conditions)
		}
		return nil
	})
}

func rulesOf(site string) (int, error) {
	var rules okv1.RuleList
	if err := k8s.List(ctx, &rules, client.InNamespace("auth")); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rules.Items {
		for _, o := range r.OwnerReferences {
			if o.Kind == "Site" && o.Name == site {
				n++
			}
		}
	}
	return n, nil
}

func TestSiteUnderAForeignZoneIsRefused(t *testing.T) {
	if err := k8s.Create(ctx, newSite("intruder", "shop.foreign.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := k8s.Create(ctx, newSite("tenant", "shop.owned.example.com")); err != nil {
		t.Fatal(err)
	}
	validated(t, "intruder", metav1.ConditionFalse, validate.ReasonZoneNotOwned)
	validated(t, "tenant", metav1.ConditionTrue, "Valid")
	eventually(t, "owned site has Rules", func() error {
		if n, err := rulesOf("tenant"); err != nil || n == 0 {
			return fmt.Errorf("rules %d %v", n, err)
		}
		return nil
	})
	consistently(t, "refused site writes no children", 2*time.Second, func() error {
		if n, err := rulesOf("intruder"); err != nil || n != 0 {
			return fmt.Errorf("rules %d %v", n, err)
		}
		return absent(&networkingv1.Ingress{}, "site-intruder")
	})
}
