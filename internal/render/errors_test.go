package render

import (
	"strings"
	"testing"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
)

func okh(name, cfg string) *okv1.Handler {
	h := &okv1.Handler{Handler: name}
	if cfg != "" {
		h.Config = raw(cfg)
	}
	return h
}

// The sandbox bug: a redirect with a `when` next to a json without one (it
// inherits the gateway's, which has none there) → both answer a browser's 403.
func TestAmbiguousErrorsFindsTheSandboxBug(t *testing.T) {
	got := AmbiguousErrors([]*okv1.Handler{
		okh("redirect", `{"to":"https://x/paused","when":[{"error":["forbidden"],"request":{"header":{"accept":["text/html"]}}}]}`),
		okh("json", ""),
	})
	if !strings.Contains(strings.Join(got, "\n"), "#1 (redirect) and #2 (json): forbidden for Accept text/html") {
		t.Fatalf("%v", got)
	}
	// an explicit empty when also matches everything
	if len(AmbiguousErrors([]*okv1.Handler{okh("json", `{"when":[]}`), okh("redirect", `{"to":"https://x","when":[{"error":["forbidden"]}]}`)})) == 0 {
		t.Fatal("when: [] matches everything")
	}
	// a single handler cannot be ambiguous
	if got := AmbiguousErrors([]*okv1.Handler{okh("json", "")}); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

func TestAcceptMatching(t *testing.T) {
	cases := []struct {
		accept string
		types  []string
		want   bool
	}{
		{"", []string{"application/octet-stream"}, true}, // no header reads as octet-stream
		{"*/*", []string{"application/json"}, false},     // a request's */* matches only */*
		{"*/*", []string{"*/*"}, true},
		{"text/html,*/*;q=0.8", []string{"text/html"}, true},
		{"application/json", []string{"application/*"}, true},
		{"application/json, text/plain, */*", []string{"text/html"}, false},
	}
	for _, c := range cases {
		if got := acceptMatches(c.accept, c.types); got != c.want {
			t.Errorf("%q vs %v: got %v", c.accept, c.types, got)
		}
	}
}

// Every error handler set the operator renders itself is unambiguous and each
// handler owns its `when` (never the gateway's, which differs per environment).
func TestPausedErrorsUnambiguous(t *testing.T) {
	for _, redirect := range []string{"", "https://auth.dev.example.com/paused"} {
		cfg := config.Default()
		cfg.PausedRedirectURL = redirect
		for _, r := range PausedRules(testSite(), cfg) {
			if a := AmbiguousErrors(r.Spec.Errors); len(a) != 0 {
				t.Errorf("redirect %q: %v", redirect, a)
			}
			for _, h := range r.Spec.Errors {
				if _, own, _ := when(h); !own {
					t.Errorf("redirect %q: %s inherits the gateway's when", redirect, h.Handler)
				}
			}
		}
	}
	// browsers get the paused page, API clients json
	cfg := config.Default()
	cfg.PausedRedirectURL = "https://auth.dev.example.com/paused"
	errs := PausedRules(testSite(), cfg)[0].Spec.Errors
	pick := func(accept string) string {
		for _, h := range errs {
			w, own, _ := when(h)
			if matches(w, own, "forbidden", accept) {
				return h.Handler
			}
		}
		return "fallback"
	}
	for accept, want := range map[string]string{
		"text/html,application/xhtml+xml,*/*;q=0.8": "redirect",
		"application/json":                          "json",
		"":                                          "json",
		"*/*":                                       "fallback",
	} {
		if got := pick(accept); got != want {
			t.Errorf("forbidden, Accept %q: %s, want %s", accept, got, want)
		}
	}
}
