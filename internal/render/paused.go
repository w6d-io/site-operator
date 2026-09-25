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
	errs := []*okv1.Handler{}
	if cfg.PausedRedirectURL != "" {
		to := cfg.PausedRedirectURL + "?site=" + url.QueryEscape(site.Name)
		errs = append(errs, &okv1.Handler{Handler: "redirect", Config: rawJSON(map[string]any{
			"to":   to,
			"when": []any{map[string]any{"error": []any{"forbidden"}, "request": map[string]any{"header": map[string]any{"accept": []any{"text/html"}}}}},
		})})
	}
	errs = append(errs, &okv1.Handler{Handler: "json"})

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

func rawJSON(v any) *runtime.RawExtension {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return &runtime.RawExtension{Raw: canonical(b)}
}
