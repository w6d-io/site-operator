package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/loaded"
	"github.com/w6d-io/site-operator/internal/render"
)

// timedOutRecheck is the slow recheck once RulesLoaded has timed out.
const timedOutRecheck = 30 * time.Second

// LoadChecker reports whether every gateway pod serves the given rules
// (Oathkeeper rule id → match URL); loaded.Prober reads each pod's GET /rules.
type LoadChecker interface {
	Check(ctx context.Context, want map[string]string) (loaded.Report, error)
}

// loadClock remembers, per Site, when its current rule set was written and how
// long the gateway pods took to load it (in memory: lost on restart, which only
// loses the latency figure).
type loadClock struct {
	mu    sync.Mutex
	sites map[types.NamespacedName]*loadMark
}

type loadMark struct {
	set    string        // hash of the wanted rules
	since  time.Time     // when that set was first written
	loaded time.Duration // latency once every pod served it (0: not yet)
}

// mark returns the Site's mark for rule set set, starting a new one when the set changed.
func (c *loadClock) mark(key types.NamespacedName, set string, now time.Time) *loadMark {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sites == nil {
		c.sites = map[types.NamespacedName]*loadMark{}
	}
	m := c.sites[key]
	if m == nil || m.set != set {
		m = &loadMark{set: set, since: now}
		c.sites[key] = m
	}
	return m
}

func (c *loadClock) forget(key types.NamespacedName) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sites, key)
}

// wantedRules is what the gateway must serve for desired: id → match URL, as maester writes it.
func wantedRules(desired []*okv1.Rule) map[string]string {
	want := make(map[string]string, len(desired))
	for _, r := range desired {
		o := render.ToOathkeeper(r)
		want[o.ID] = o.Match.URL
	}
	return want
}

// setRulesLoaded probes the gateway pods once and sets RulesLoaded. It never
// blocks: while pods lag it returns how soon to look again (backing off), and
// after the timeout it reports Timeout and rechecks slowly.
func (r *SiteReconciler) setRulesLoaded(ctx context.Context, site *authv1.Site, desired []*okv1.Rule) time.Duration {
	if r.Loaded == nil {
		setCondition(site, authv1.ConditionRulesLoaded, metav1.ConditionTrue, "NotChecked",
			"no gateway pod selector is configured; RulesSynced is the last signal")
		return 0
	}
	want := wantedRules(desired)
	m := r.clock.mark(client.ObjectKeyFromObject(site), render.Hash(want), time.Now())
	if c := meta.FindStatusCondition(site.Status.Conditions, authv1.ConditionRulesSynced); c == nil || c.Status != metav1.ConditionTrue {
		// maester's status update on each Rule triggers the next reconcile
		setCondition(site, authv1.ConditionRulesLoaded, metav1.ConditionFalse, "WaitingForMaester",
			"maester has not acknowledged every rule yet")
		return 0
	}
	rep, err := r.Loaded.Check(ctx, want)
	elapsed := time.Since(m.since)
	if err == nil && rep.Done() {
		if m.loaded == 0 {
			m.loaded = max(elapsed, time.Millisecond)
		}
		setCondition(site, authv1.ConditionRulesLoaded, metav1.ConditionTrue, "Loaded",
			fmt.Sprintf("%s, %s after they were written", rep, m.loaded.Round(time.Millisecond)))
		return 0
	}
	if m.loaded != 0 {
		// it was loaded and no longer is (a pod restarted, a rule vanished): start over
		m.since, m.loaded, elapsed = time.Now(), 0, 0
	}
	msg := rep.String()
	if err != nil {
		msg = err.Error()
	}
	status, reason, after := loadingState(elapsed, r.Config.RulesLoadedTimeout)
	setCondition(site, authv1.ConditionRulesLoaded, status, reason, msg)
	return after
}

// loadingState is the RulesLoaded reason and recheck delay while pods lag:
// poll fast right after a write (a reload takes tens of ms), then back off.
func loadingState(elapsed, timeout time.Duration) (metav1.ConditionStatus, string, time.Duration) {
	switch {
	case elapsed >= timeout:
		return metav1.ConditionFalse, "Timeout", timedOutRecheck
	case elapsed < time.Second:
		return metav1.ConditionFalse, "Loading", 20 * time.Millisecond
	case elapsed < 10*time.Second:
		return metav1.ConditionFalse, "Loading", 500 * time.Millisecond
	default:
		return metav1.ConditionFalse, "Loading", 2 * time.Second
	}
}
