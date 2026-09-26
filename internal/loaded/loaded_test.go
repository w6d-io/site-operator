package loaded

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// gateway fakes one Oathkeeper pod's GET /rules (limit/offset paging like v25.4.0).
func gateway(t *testing.T, rules []Rule, delay time.Duration) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		if r.URL.Path != "/rules" {
			http.NotFound(w, r)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if limit > pageSize || limit <= 0 {
			t.Errorf("limit %d", limit)
		}
		end := min(offset+limit, len(rules))
		page := []Rule{}
		if offset < len(rules) {
			page = rules[offset:end]
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(s.Close)
	return s
}

func rule(id, url string) Rule {
	r := Rule{ID: id}
	r.Match.URL = url
	return r
}

func pod(name, ip string, ready bool) *corev1.Pod {
	st := corev1.ConditionFalse
	if ready {
		st = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth", Labels: map[string]string{"app.kubernetes.io/name": "oathkeeper"}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: st}}},
	}
}

// prober routes each pod IP to its fake gateway.
func prober(t *testing.T, servers map[string]*httptest.Server, objs ...client.Object) *Prober {
	t.Helper()
	dial := &net.Dialer{}
	tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		s, ok := servers[host]
		if !ok {
			return nil, fmt.Errorf("no route to %s", host)
		}
		return dial.DialContext(ctx, network, strings.TrimPrefix(s.URL, "http://"))
	}}
	return &Prober{
		Reader:    fake.NewClientBuilder().WithObjects(objs...).Build(),
		Namespace: "auth",
		Selector:  labels.SelectorFromSet(labels.Set{"app.kubernetes.io/name": "oathkeeper"}),
		Port:      4456,
		Timeout:   300 * time.Millisecond,
		HTTP:      &http.Client{Transport: tr},
	}
}

var want = map[string]string{
	"shop-browser-1a2b3c4d.auth": "<https?>://shop.dev.example.com/<.*>",
	"shop-public-5e6f7a8b.auth":  "<https?>://shop.dev.example.com/health",
}

func TestEveryReadyPodLoaded(t *testing.T) {
	rules := []Rule{
		rule("shop-browser-1a2b3c4d.auth", "<https?>://shop.dev.example.com/<.*>"),
		rule("shop-public-5e6f7a8b.auth", "<https?>://shop.dev.example.com/health"),
		rule("kuma.auth", "<https?>://kuma.dev.example.com/<.*>"),
	}
	p := prober(t, map[string]*httptest.Server{"10.0.0.1": gateway(t, rules, 0), "10.0.0.2": gateway(t, rules, 0)},
		pod("ok-a", "10.0.0.1", true), pod("ok-b", "10.0.0.2", true),
		pod("ok-c", "10.0.0.3", false)) // not Ready: takes no traffic, not probed
	rep, err := p.Check(context.Background(), want)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Done() || rep.Pods != 2 || rep.Loaded != 2 {
		t.Fatalf("%+v", rep)
	}
}

func TestPodMissingOrStaleRule(t *testing.T) {
	full := []Rule{
		rule("shop-browser-1a2b3c4d.auth", "<https?>://shop.dev.example.com/<.*>"),
		rule("shop-public-5e6f7a8b.auth", "<https?>://shop.dev.example.com/health"),
	}
	cases := map[string]struct {
		rules []Rule
		msg   string
	}{
		"missing": {full[:1], "ok-b: rule shop-public-5e6f7a8b.auth not loaded"},
		"retired copy": {[]Rule{full[0], rule("shop-public-5e6f7a8b.auth", "https://shop-public-5e6f7a8b.retired.invalid/")},
			"ok-b: rule shop-public-5e6f7a8b.auth loaded with an older match"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := prober(t, map[string]*httptest.Server{"10.0.0.1": gateway(t, full, 0), "10.0.0.2": gateway(t, tc.rules, 0)},
				pod("ok-a", "10.0.0.1", true), pod("ok-b", "10.0.0.2", true))
			rep, err := p.Check(context.Background(), want)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Done() || rep.Loaded != 1 || rep.Pending != tc.msg {
				t.Fatalf("%+v", rep)
			}
		})
	}
}

func TestPagesThroughEveryRule(t *testing.T) {
	var rules []Rule
	for i := range 2*pageSize + 7 {
		rules = append(rules, rule(fmt.Sprintf("platform-%04d.auth", i), "https://x/"))
	}
	rules = append(rules, rule("shop-browser-1a2b3c4d.auth", "<https?>://shop.dev.example.com/<.*>"),
		rule("shop-public-5e6f7a8b.auth", "<https?>://shop.dev.example.com/health"))
	p := prober(t, map[string]*httptest.Server{"10.0.0.1": gateway(t, rules, 0)}, pod("ok-a", "10.0.0.1", true))
	rep, err := p.Check(context.Background(), want)
	if err != nil || !rep.Done() {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestSlowOrDownPodIsBounded(t *testing.T) {
	p := prober(t, map[string]*httptest.Server{"10.0.0.1": gateway(t, nil, time.Second)},
		pod("ok-a", "10.0.0.1", true), pod("ok-b", "10.0.0.9", true))
	start := time.Now()
	rep, err := p.Check(context.Background(), want)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 800*time.Millisecond {
		t.Fatalf("probe not bounded by its timeout: %s", time.Since(start))
	}
	if rep.Done() || rep.Loaded != 0 || !strings.HasPrefix(rep.Pending, "ok-a: read rules:") {
		t.Fatalf("%+v", rep)
	}
}

func TestNoReadyPod(t *testing.T) {
	p := prober(t, nil, pod("ok-a", "10.0.0.1", false))
	rep, err := p.Check(context.Background(), want)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Done() || rep.String() != "no Ready gateway pod" {
		t.Fatalf("%+v", rep)
	}
}
