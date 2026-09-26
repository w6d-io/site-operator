package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
	"github.com/w6d-io/site-operator/internal/loaded"
	"github.com/w6d-io/site-operator/internal/render"
	"github.com/w6d-io/site-operator/internal/testenv"
	"github.com/w6d-io/site-operator/internal/validate"
)

var (
	gw     = &fakeGateway{held: map[string]bool{}, calls: map[string]int{}, want: map[string]map[string]string{}}
	k8s    client.Client
	cfg    *config.Config
	watchC client.WithWatch
)

// testValidator refuses patterns containing "((" (like the mock) and is
// unavailable for sites whose name starts with "down-".
type testValidator struct{ mock validate.Mock }

func (v *testValidator) Validate(ctx context.Context, cand, others []render.OathkeeperRule) error {
	for _, r := range cand {
		if strings.HasPrefix(r.ID, "down-") {
			return errors.New("dial tcp gatekit:8080: connection refused")
		}
	}
	return v.mock.Validate(ctx, cand, others)
}

// fakeGateway plays two Oathkeeper pods: both serve every Rule maester
// acknowledged, except the Rules of held sites, which pod b has not loaded yet.
type fakeGateway struct {
	mu    sync.Mutex
	held  map[string]bool
	calls map[string]int
	want  map[string]map[string]string
}

func (g *fakeGateway) Check(_ context.Context, want map[string]string) (loaded.Report, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for id := range want {
		i := strings.LastIndex(id, "-")
		if i < 0 || strings.LastIndex(id[:i], "-") < 0 {
			continue
		}
		site := id[:strings.LastIndex(id[:i], "-")] // <site>-<gate>-<hash8>.auth
		g.calls[site]++
		g.want[site] = want
		if g.held[site] {
			return loaded.Report{Pods: 2, Loaded: 1, Pending: "ok-b: rule " + id + " not loaded"}, nil
		}
	}
	return loaded.Report{Pods: 2, Loaded: 2}, nil
}

func (g *fakeGateway) hold(site string)    { g.mu.Lock(); g.held[site] = true; g.mu.Unlock() }
func (g *fakeGateway) release(site string) { g.mu.Lock(); delete(g.held, site); g.mu.Unlock() }
func (g *fakeGateway) checks(site string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls[site]
}
func (g *fakeGateway) lastWant(site string) map[string]string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.want[site]
}

func TestMain(m *testing.M) {
	env := testenv.New()
	if env == nil {
		fmt.Println("envtest binaries not found (run: setup-envtest use " + testenv.K8sVersion + "); skipping controller tests")
		os.Exit(0)
	}
	rc, err := env.Start()
	if err != nil {
		panic(err)
	}
	cfg = config.Default()
	cfg.GatewayRolloutTimeout = 2 * time.Second
	cfg.IngressAnnotations = map[string]string{"nginx.ingress.kubernetes.io/proxy-read-timeout": "300"}

	mgr, err := ctrl.NewManager(rc, ctrl.Options{Scheme: testenv.Scheme(), Metrics: metricsserver.Options{BindAddress: "0"}})
	if err != nil {
		panic(err)
	}
	r := &SiteReconciler{
		Client:    mgr.GetClient(),
		Config:    cfg,
		Validator: &testValidator{mock: validate.Mock{Invalid: []string{"(("}}},
		Recorder:  mgr.GetEventRecorderFor("site-operator"),
		Loaded:    gw,
	}
	if err := r.SetupWithManager(mgr); err != nil {
		panic(err)
	}
	g := &GatewayReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Config: cfg,
		Recorder: mgr.GetEventRecorderFor("site-operator"), Loaded: gw}
	if err := g.SetupWithManager(mgr); err != nil {
		panic(err)
	}
	z := &ZoneReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Config: cfg, Recorder: mgr.GetEventRecorderFor("site-operator")}
	if err := z.SetupWithManager(mgr); err != nil {
		panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := mgr.Start(ctx); err != nil {
			panic(err)
		}
	}()
	k8s, err = client.New(rc, client.Options{Scheme: testenv.Scheme()})
	if err != nil {
		panic(err)
	}
	if watchC, err = client.NewWithWatch(rc, client.Options{Scheme: testenv.Scheme()}); err != nil {
		panic(err)
	}
	if err := k8s.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "auth"}}); err != nil {
		panic(err)
	}
	// the shipped output policies (Ingress, Rule) bound everything the controller
	// writes; the Site and hosts policies are left out so the operator's own
	// refusals are tested as the safety net for Sites that bypass admission
	if err := testenv.ApplyFiles(ctx, k8s, filepath.Join(testenv.Root(), "config", "rbac"), "zones_configmap.yaml"); err != nil {
		panic(err)
	}
	if err := testenv.ApplyFiles(ctx, k8s, filepath.Join(testenv.Root(), "config", "admission"),
		"params.yaml", "ingress_policy.yaml", "rule_policy.yaml"); err != nil {
		panic(err)
	}
	if err := setupDevZone(ctx); err != nil {
		panic(err)
	}
	if err := setupGatewayPlatform(ctx); err != nil {
		panic(err)
	}
	code := m.Run()
	cancel()
	_ = env.Stop()
	os.Exit(code)
}

// eventually polls f until it returns nil or 15 s pass.
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

// consistently checks f keeps returning nil for d.
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

// setupDevZone creates Zone dev (dev.example.com, default certificate) and
// plays the ingress controller for its wildcard Ingress, so the zone is Ready.
func setupDevZone(ctx context.Context) error {
	zone := &authv1.Zone{ObjectMeta: metav1.ObjectMeta{Name: "dev"},
		Spec: authv1.ZoneSpec{Domain: "dev.example.com", TLS: authv1.ZoneTLS{Mode: authv1.ZoneTLSDefault}}}
	if err := k8s.Create(ctx, zone); err != nil {
		return err
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		ing := &networkingv1.Ingress{}
		err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "zone-dev"}, ing)
		if err == nil {
			ing.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{{Hostname: "a884b7ca.elb.amazonaws.com"}}
			if err = k8s.Status().Update(ctx, ing); err == nil {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("zone-dev ingress: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
