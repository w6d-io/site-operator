// Package loaded reads which access rules each Oathkeeper pod has actually
// loaded (API port, GET /rules). maester only knows it wrote its own file; this
// is the only signal that a rule is enforced on every gateway pod.
package loaded

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// pageSize is Oathkeeper's maximum page size for GET /rules.
const pageSize = 500

// Rule is the part of a loaded rule the check compares.
type Rule struct {
	ID    string `json:"id"`
	Match struct {
		URL string `json:"url"`
	} `json:"match"`
}

// Report is what the gateway pods had loaded at one instant.
type Report struct {
	// Pods is the number of Ready gateway pods probed; Loaded how many had every wanted rule.
	Pods, Loaded int
	// Pending names the first pod still missing something, and why.
	Pending string
}

// Done reports whether every Ready pod had every wanted rule.
func (r Report) Done() bool { return r.Pods > 0 && r.Loaded == r.Pods }

func (r Report) String() string {
	if r.Pods == 0 {
		return "no Ready gateway pod"
	}
	s := fmt.Sprintf("%d/%d gateway pods loaded the rules", r.Loaded, r.Pods)
	if r.Pending != "" {
		s += "; " + r.Pending
	}
	return s
}

// Prober lists the Ready gateway pods (get/list only: no watch, no cache) and
// reads each pod's rules concurrently, every request bounded by Timeout.
type Prober struct {
	Reader    client.Reader
	Namespace string
	Selector  labels.Selector
	Port      int
	Timeout   time.Duration
	HTTP      *http.Client
}

// Check reports, for each Ready gateway pod, whether it serves every rule in
// want (rule id → match URL). A rule counts only with the same match URL, so a
// retired copy under the same id does not.
func (p *Prober) Check(ctx context.Context, want map[string]string) (Report, error) {
	var pods corev1.PodList
	if err := p.Reader.List(ctx, &pods, client.InNamespace(p.Namespace), client.MatchingLabelsSelector{Selector: p.Selector}); err != nil {
		return Report{}, fmt.Errorf("list gateway pods: %w", err)
	}
	var ready []corev1.Pod
	for _, pod := range pods.Items {
		if podReady(&pod) {
			ready = append(ready, pod)
		}
	}
	slices.SortFunc(ready, func(a, b corev1.Pod) int {
		if a.Name < b.Name {
			return -1
		}
		return 1
	})
	missing := make([]string, len(ready))
	var wg sync.WaitGroup
	for i := range ready {
		wg.Go(func() { missing[i] = p.missing(ctx, &ready[i], want) })
	}
	wg.Wait()
	rep := Report{Pods: len(ready)}
	for i, m := range missing {
		if m == "" {
			rep.Loaded++
		} else if rep.Pending == "" {
			rep.Pending = ready[i].Name + ": " + m
		}
	}
	return rep, nil
}

// missing returns "" when pod serves every wanted rule, else the reason it does not.
func (p *Prober) missing(ctx context.Context, pod *corev1.Pod, want map[string]string) string {
	got, err := p.rules(ctx, pod.Status.PodIP)
	if err != nil {
		return err.Error()
	}
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		url, ok := got[id]
		if !ok {
			return "rule " + id + " not loaded"
		}
		if url != want[id] {
			return "rule " + id + " loaded with an older match"
		}
	}
	return ""
}

// rules reads every page of GET /rules from one pod: id → match URL.
func (p *Prober) rules(ctx context.Context, ip string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	base := "http://" + net.JoinHostPort(ip, strconv.Itoa(p.Port)) + "/rules?limit=" + strconv.Itoa(pageSize) + "&offset="
	out := map[string]string{}
	for offset := 0; ; offset += pageSize {
		page, err := p.page(ctx, base+strconv.Itoa(offset))
		if err != nil {
			return nil, err
		}
		for _, r := range page {
			out[r.ID] = r.Match.URL
		}
		if len(page) < pageSize {
			return out, nil
		}
	}
}

func (p *Prober) page(ctx context.Context, url string) ([]Rule, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := p.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read rules: HTTP %d", res.StatusCode)
	}
	var page []Rule
	if err := json.NewDecoder(res.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	return page, nil
}

func podReady(pod *corev1.Pod) bool {
	if !pod.DeletionTimestamp.IsZero() || pod.Status.PodIP == "" || pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
