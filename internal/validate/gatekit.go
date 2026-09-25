package validate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/w6d-io/site-operator/internal/render"
)

// Gatekit calls the gatekit service (the real Oathkeeper compiler and matcher).
type Gatekit struct {
	BaseURL string
	Client  *http.Client
}

// NewGatekit returns a client with a short timeout: a slow gatekit must not
// stall reconciles, and an unanswered check never lets a rule through.
func NewGatekit(baseURL string) *Gatekit {
	return &Gatekit{BaseURL: strings.TrimRight(baseURL, "/"), Client: &http.Client{Timeout: 5 * time.Second}}
}

type compilePattern struct {
	ID      string   `json:"id"`
	URL     string   `json:"url"`
	Methods []string `json:"methods"`
}

type compileResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type overlap struct {
	A          string `json:"a"`
	B          string `json:"b"`
	Method     string `json:"method"`
	ExampleURL string `json:"exampleUrl"`
}

type invalidRule struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

// Validate compiles every candidate pattern (POST /compile), then asks for
// overlaps across the candidate and every other rule in the namespace
// (POST /overlap). Any rule the matcher refuses ("invalid") refuses the Site:
// one such rule already breaks the gateway for its methods, so nothing more is
// written until it is fixed. Overlaps refuse the Site when they involve one of
// its rules; an overlap between two other sites is theirs to fix and must not
// lock every site out. Contract: gatekit/README.md.
func (g *Gatekit) Validate(ctx context.Context, candidate, others []render.OathkeeperRule) error {
	pats := make([]compilePattern, 0, len(candidate))
	ids := make([]string, 0, len(candidate))
	var hosts []string
	for _, r := range candidate {
		pats = append(pats, compilePattern{ID: r.ID, URL: r.Match.URL, Methods: r.Match.Methods})
		ids = append(ids, r.ID)
		if h := matchHost(r.Match.URL); h != "" && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	var cres struct {
		Results []compileResult `json:"results"`
	}
	if err := g.post(ctx, "/compile", map[string]any{"patterns": pats}, &cres); err != nil {
		return err
	}
	if len(cres.Results) != len(pats) {
		return fmt.Errorf("gatekit /compile answered %d results for %d patterns", len(cres.Results), len(pats))
	}
	for _, r := range cres.Results {
		if !r.OK {
			return refuse(ReasonPatternInvalid, "rule %s: %s", r.ID, r.Error)
		}
	}

	all := append(append([]render.OathkeeperRule{}, others...), candidate...)
	req := map[string]any{"rules": all}
	if len(hosts) > 0 {
		req["hosts"] = hosts
	}
	var ores struct {
		Overlaps []overlap     `json:"overlaps"`
		Invalid  []invalidRule `json:"invalid"`
	}
	if err := g.post(ctx, "/overlap", req, &ores); err != nil {
		return err
	}
	for _, inv := range ores.Invalid {
		if slices.Contains(ids, inv.ID) {
			return refuse(ReasonPatternInvalid, "rule %s: %s", inv.ID, inv.Error)
		}
		return refuse(ReasonPatternInvalid, "existing rule %s is invalid (%s); fix it before changing sites", inv.ID, inv.Error)
	}
	for _, o := range ores.Overlaps {
		if slices.Contains(ids, o.A) || slices.Contains(ids, o.B) {
			return refuse(ReasonRuleOverlap, "%s %s matches both %s and %s", o.Method, o.ExampleURL, o.A, o.B)
		}
	}
	return nil
}

// matchHost extracts the literal host of a match URL ("" if not literal).
func matchHost(url string) string {
	for _, p := range schemePrefixes {
		if rest, ok := strings.CutPrefix(url, p); ok {
			h, _, _ := strings.Cut(rest, "/")
			return h
		}
	}
	return ""
}

func (g *Gatekit) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.Client.Do(req)
	if err != nil {
		return fmt.Errorf("gatekit %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("gatekit %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gatekit %s: HTTP %d: %s", path, resp.StatusCode, bytes.TrimSpace(raw))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("gatekit %s: %w", path, err)
	}
	return nil
}

// Mock is an in-memory Validator for tests: it refuses any candidate whose
// match URL contains one of Invalid, and fails with Err when set.
type Mock struct {
	Invalid []string
	Err     error
	Calls   int
}

func (m *Mock) Validate(_ context.Context, candidate, _ []render.OathkeeperRule) error {
	m.Calls++
	if m.Err != nil {
		return m.Err
	}
	for _, r := range candidate {
		for _, bad := range m.Invalid {
			if strings.Contains(r.Match.URL, bad) {
				return refuse(ReasonPatternInvalid, "rule %s: pattern %q does not compile", r.ID, r.Match.URL)
			}
		}
	}
	return nil
}
