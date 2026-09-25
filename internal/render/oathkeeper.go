package render

import (
	"encoding/json"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
)

// OathkeeperRule is the rule as Oathkeeper (and gatekit) reads it, i.e. what
// maester writes into the rules file.
type OathkeeperRule struct {
	ID       string `json:"id"`
	Upstream struct {
		URL          string `json:"url"`
		PreserveHost bool   `json:"preserve_host"`
		StripPath    string `json:"strip_path,omitempty"`
	} `json:"upstream"`
	Match struct {
		URL     string   `json:"url"`
		Methods []string `json:"methods"`
	} `json:"match"`
	Authenticators []OathkeeperHandler `json:"authenticators"`
	Authorizer     OathkeeperHandler   `json:"authorizer"`
	Mutators       []OathkeeperHandler `json:"mutators"`
	Errors         []OathkeeperHandler `json:"errors,omitempty"`
}

// OathkeeperHandler is one handler with its raw config.
type OathkeeperHandler struct {
	Handler string          `json:"handler"`
	Config  json.RawMessage `json:"config,omitempty"`
}

// ToOathkeeper converts a Rule CR the way maester does: id = <name>.<namespace>,
// and the same defaults for a missing authorizer (deny) and mutators (noop).
func ToOathkeeper(r *okv1.Rule) OathkeeperRule {
	var o OathkeeperRule
	o.ID = r.Name + "." + r.Namespace
	if u := r.Spec.Upstream; u != nil {
		o.Upstream.URL = u.URL
		if u.PreserveHost != nil {
			o.Upstream.PreserveHost = *u.PreserveHost
		}
		if u.StripPath != nil {
			o.Upstream.StripPath = *u.StripPath
		}
	}
	if m := r.Spec.Match; m != nil {
		o.Match.URL, o.Match.Methods = m.URL, m.Methods
	}
	o.Authenticators = okHandlers(r.Spec.Authenticators, "unauthorized")
	o.Authorizer = OathkeeperHandler{Handler: "deny"}
	if r.Spec.Authorizer != nil {
		o.Authorizer = okHandler(r.Spec.Authorizer)
	}
	o.Mutators = okHandlers(r.Spec.Mutators, "noop")
	if len(r.Spec.Errors) > 0 {
		o.Errors = okHandlers(r.Spec.Errors, "")
	}
	return o
}

func okHandler(h *okv1.Handler) OathkeeperHandler {
	out := OathkeeperHandler{Handler: h.Handler}
	if h.Config != nil && len(h.Config.Raw) > 0 {
		out.Config = json.RawMessage(h.Config.Raw)
	}
	return out
}

func okHandlers(in []*okv1.Handler, def string) []OathkeeperHandler {
	if len(in) == 0 {
		if def == "" {
			return nil
		}
		return []OathkeeperHandler{{Handler: def}}
	}
	out := make([]OathkeeperHandler, 0, len(in))
	for _, h := range in {
		out = append(out, okHandler(h))
	}
	return out
}
