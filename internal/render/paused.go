package render

import (
	"encoding/json"
	"net/url"
	"strconv"

	"k8s.io/apimachinery/pkg/runtime"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
)

// PausedGate is the gate label of the deny Rules that replace a paused Site's gates.
const PausedGate = "paused"

var allMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

// PausedRules renders one deny Rule per host (site-ux §20.2): every request is
// refused with 403, browsers are redirected to the "site paused" page when one
// is configured, JSON clients get the json error. The Site's gate Rules are
// swapped out (and back on resume) with the same retire/create/delete order.
func PausedRules(site *authv1.Site, cfg *config.Config) []*okv1.Rule {
	errs := PausedErrors(site, cfg)
	out := make([]*okv1.Rule, 0, len(site.Spec.Hosts))
	for i, h := range site.Spec.Hosts {
		preserve := false
		spec := okv1.RuleSpec{
			Upstream:       &okv1.Upstream{URL: UpstreamURL(site.Spec.Upstream), PreserveHost: &preserve},
			Match:          &okv1.Match{URL: "<https?>://" + h + "/<.*>", Methods: append([]string{}, allMethods...)},
			Authenticators: []*okv1.Handler{{Handler: "noop"}},
			Authorizer:     &okv1.Handler{Handler: "deny"},
			Mutators:       []*okv1.Handler{{Handler: "noop"}},
			Errors:         errs,
		}
		if cfg.RulesConfigMap != "" {
			cm := cfg.RulesConfigMap
			spec.ConfigMapName = &cm
		}
		hash := Hash(spec)
		gate := PausedGate + "-" + strconv.Itoa(i)
		m := meta(site, site.Name+"-"+gate+"-"+hash, hash)
		m.Labels[GateLabel] = gate
		out = append(out, &okv1.Rule{ObjectMeta: m, Spec: spec})
	}
	return out
}

// machineTypes are the Accept types API clients send (application/octet-stream:
// no Accept header at all, as Oathkeeper reads it).
var machineTypes = []any{"application/json", "application/problem+json", "application/octet-stream"}

// PausedErrors are the paused Rule's error handlers. Each carries its own
// `when` (a rule's `when` replaces the gateway's, even when empty) and no
// (error, Accept) pair matches two of them: two matches is a 500 in Oathkeeper.
// Browsers (text/html) are redirected to the paused page; API clients get json;
// an Accept of only */* matches neither and takes the gateway fallback.
// Without a paused page, json answers everything (when: []).
func PausedErrors(site *authv1.Site, cfg *config.Config) []*okv1.Handler {
	if cfg.PausedRedirectURL == "" {
		return []*okv1.Handler{{Handler: "json", Config: rawJSON(map[string]any{"when": []any{}})}}
	}
	to := cfg.PausedRedirectURL + "?site=" + url.QueryEscape(site.Name)
	return []*okv1.Handler{
		{Handler: "redirect", Config: rawJSON(map[string]any{
			"to":   to,
			"when": []any{map[string]any{"error": []any{"forbidden"}, "request": map[string]any{"header": map[string]any{"accept": []any{"text/html"}}}}},
		})},
		{Handler: "json", Config: rawJSON(map[string]any{
			"when": []any{
				map[string]any{"error": []any{"unauthorized", "not_found", "internal_server_error"}},
				map[string]any{"error": []any{"forbidden"}, "request": map[string]any{"header": map[string]any{"accept": machineTypes}}},
			},
		})},
	}
}

func rawJSON(v any) *runtime.RawExtension {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return &runtime.RawExtension{Raw: canonical(b)}
}
