package render

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
)

// How Oathkeeper v25.4.0 picks a rule's error handler (pipeline/errors/when.go,
// proxy/request_handler.go): every handler whose `when` matches the error is a
// candidate; two candidates answer 500 ("found more than one error handler"),
// none falls back to the gateway's errors.fallback. A rule handler's `when`
// replaces the gateway's, even when empty ([] matches everything); one without
// `when` inherits the gateway's, which this operator cannot see, so it is taken
// as matching everything. Within a `when`, entries are OR'd; an entry's `error`
// must list the error, its Accept types must match the request's: a handler type
// */* matches anything, type/* any subtype, otherwise verbatim; a request's */*
// matches only a handler's */*; no Accept header reads as application/octet-stream.

type whenEntry struct {
	Error   []string `json:"error"`
	Request *struct {
		Header *struct {
			Accept []string `json:"accept"`
		} `json:"header"`
	} `json:"request"`
}

// WhenErrors are the error names Oathkeeper accepts in a `when`.
var WhenErrors = []string{"unauthorized", "forbidden", "not_found", "internal_server_error"}

// probeAccepts are the Accept headers the ambiguity check tries ("" = none sent),
// besides every type a handler names.
var probeAccepts = []string{
	"", "*/*",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"application/json, text/plain, */*",
	"application/json", "application/problem+json", "text/html", "text/plain",
}

// when returns a handler's own `when` (nil, false when it has none).
func when(h *okv1.Handler) ([]whenEntry, bool, error) {
	if h.Config == nil || len(h.Config.Raw) == 0 {
		return nil, false, nil
	}
	var cfg struct {
		When *[]whenEntry `json:"when"`
	}
	if err := json.Unmarshal(h.Config.Raw, &cfg); err != nil {
		return nil, false, err
	}
	if cfg.When == nil {
		return nil, false, nil
	}
	return *cfg.When, true, nil
}

func parseAccept(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if t := strings.TrimSpace(strings.SplitN(p, ";", 2)[0]); t != "" {
			out = append(out, strings.ToLower(t))
		}
	}
	return out
}

func acceptMatches(accept string, types []string) bool {
	if accept == "" {
		accept = "application/octet-stream"
	}
	for _, a := range parseAccept(accept) {
		for _, m := range types {
			m = strings.ToLower(m)
			if m == "*/*" || (strings.HasSuffix(m, "/*") && strings.TrimSuffix(m, "/*") == strings.SplitN(a, "/", 2)[0]) || a == m {
				return true
			}
		}
	}
	return false
}

func matches(w []whenEntry, own bool, errName, accept string) bool {
	if !own || len(w) == 0 {
		return true
	}
	return slices.ContainsFunc(w, func(e whenEntry) bool {
		if len(e.Error) > 0 && !slices.Contains(e.Error, errName) {
			return false
		}
		if e.Request == nil || e.Request.Header == nil || len(e.Request.Header.Accept) == 0 {
			return true
		}
		return acceptMatches(accept, e.Request.Header.Accept)
	})
}

// AmbiguousErrors lists the (error, Accept) pairs two or more of a rule's error
// handlers would all answer (Oathkeeper then fails with 500). Empty is safe.
func AmbiguousErrors(handlers []*okv1.Handler) []string {
	if len(handlers) < 2 {
		return nil
	}
	whens := make([][]whenEntry, len(handlers))
	own := make([]bool, len(handlers))
	accepts := slices.Clone(probeAccepts)
	for i, h := range handlers {
		w, ok, err := when(h)
		if err != nil {
			return []string{fmt.Sprintf("error handler #%d (%s): %v", i+1, h.Handler, err)}
		}
		whens[i], own[i] = w, ok
		for _, e := range w {
			if e.Request != nil && e.Request.Header != nil {
				for _, t := range e.Request.Header.Accept {
					if !slices.Contains(accepts, t) {
						accepts = append(accepts, t)
					}
				}
			}
		}
	}
	var out []string
	for _, e := range WhenErrors {
		for _, a := range accepts {
			var hit []string
			for i, h := range handlers {
				if matches(whens[i], own[i], e, a) {
					hit = append(hit, fmt.Sprintf("#%d (%s)", i+1, h.Handler))
				}
			}
			if len(hit) > 1 {
				label := "Accept " + a
				if a == "" {
					label = "no Accept header"
				}
				out = append(out, fmt.Sprintf("%s: %s for %s", strings.Join(hit, " and "), e, label))
			}
		}
	}
	return out
}
