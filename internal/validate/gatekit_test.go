package validate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/w6d-io/site-operator/internal/render"
)

func okRule(id, url string) render.OathkeeperRule {
	var r render.OathkeeperRule
	r.ID, r.Match.URL, r.Match.Methods = id, url, []string{"GET"}
	return r
}

// fakeGatekit answers /compile (patterns containing "((" fail) and /overlap
// (two rules with the same match url overlap).
func fakeGatekit(t *testing.T, seen *[]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.URL.Path)
		switch r.URL.Path {
		case "/compile":
			var in struct{ Patterns []compilePattern }
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Fatal(err)
			}
			var out []compileResult
			for _, p := range in.Patterns {
				res := compileResult{ID: p.ID, OK: true}
				if strings.Contains(p.URL, "((") {
					res.OK, res.Error = false, "missing closing )"
				}
				out = append(out, res)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": out})
		case "/overlap":
			var in struct{ Rules []render.OathkeeperRule }
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Fatal(err)
			}
			ov := []overlap{}
			inv := []invalidRule{}
			for i, a := range in.Rules {
				if strings.Contains(a.Match.URL, "<**>") {
					inv = append(inv, invalidRule{ID: a.ID, Error: "invalid nested repetition"})
				}
				for _, b := range in.Rules[i+1:] {
					if a.Match.URL == b.Match.URL {
						ov = append(ov, overlap{A: a.ID, B: b.ID, Method: "GET", ExampleURL: a.Match.URL})
					}
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"overlaps": ov, "invalid": inv, "checked": 1, "probes": 1, "method": "probe"})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestGatekitValidate(t *testing.T) {
	var seen []string
	srv := fakeGatekit(t, &seen)
	defer srv.Close()
	g := NewGatekit(srv.URL + "/")
	ctx := context.Background()

	if err := g.Validate(ctx, []render.OathkeeperRule{okRule("a.auth", "https://a.dev.example.com/<.*>")}, nil); err != nil {
		t.Fatalf("valid rule refused: %v", err)
	}

	err := g.Validate(ctx, []render.OathkeeperRule{okRule("a.auth", "https://a.dev.example.com/<((>")}, nil)
	var ref *Refusal
	if !errors.As(err, &ref) || ref.Reason != ReasonPatternInvalid {
		t.Fatalf("want PatternInvalid, got %v", err)
	}

	others := []render.OathkeeperRule{okRule("b.auth", "https://a.dev.example.com/<.*>")}
	err = g.Validate(ctx, []render.OathkeeperRule{okRule("a.auth", "https://a.dev.example.com/<.*>")}, others)
	if !errors.As(err, &ref) || ref.Reason != ReasonRuleOverlap {
		t.Fatalf("want RuleOverlap, got %v", err)
	}

	// a candidate the matcher refuses at overlap time is refused too
	err = g.Validate(ctx, []render.OathkeeperRule{okRule("g.auth", "https://g.dev.example.com/<**>")}, nil)
	if !errors.As(err, &ref) || ref.Reason != ReasonPatternInvalid {
		t.Fatalf("want PatternInvalid from /overlap invalid, got %v", err)
	}

	// an invalid rule elsewhere in the namespace refuses too (gateway already broken)
	err = g.Validate(ctx, []render.OathkeeperRule{okRule("h.auth", "https://h.dev.example.com/<.*>")},
		[]render.OathkeeperRule{okRule("x.auth", "https://x.dev.example.com/<**>")})
	if !errors.As(err, &ref) || ref.Reason != ReasonPatternInvalid {
		t.Fatalf("want PatternInvalid for an invalid existing rule, got %v", err)
	}

	// overlaps among other sites only do not block this one
	others = append(others, okRule("c.auth", "https://a.dev.example.com/<.*>"))
	if err := g.Validate(ctx, []render.OathkeeperRule{okRule("d.auth", "https://d.dev.example.com/<.*>")}, others); err != nil {
		t.Fatalf("unrelated overlap blocked: %v", err)
	}
}

func TestGatekitUnavailableIsNotARefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	err := NewGatekit(srv.URL).Validate(context.Background(), []render.OathkeeperRule{okRule("a", "https://a/<.*>")}, nil)
	var ref *Refusal
	if err == nil || errors.As(err, &ref) {
		t.Fatalf("want infrastructure error, got %v", err)
	}
}
