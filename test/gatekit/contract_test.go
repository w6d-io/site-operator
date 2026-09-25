// Package gatekit runs the operator's gatekit client against the real gatekit
// binary (built from ../gatekit, or GATEKIT_URL when set), so the request and
// response shapes are checked end to end, not only against the mock.
package gatekit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
	"github.com/w6d-io/site-operator/internal/render"
	"github.com/w6d-io/site-operator/internal/testenv"
	"github.com/w6d-io/site-operator/internal/validate"
)

var baseURL string

func TestMain(m *testing.M) {
	baseURL = os.Getenv("GATEKIT_URL")
	var stop func()
	if baseURL == "" {
		var err error
		if baseURL, stop, err = startGatekit(); err != nil {
			fmt.Println("gatekit not available, skipping contract tests:", err)
			os.Exit(0)
		}
	}
	code := m.Run()
	if stop != nil {
		stop()
	}
	os.Exit(code)
}

func freeAddr() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

func startGatekit() (string, func(), error) {
	src := filepath.Join(testenv.Root(), "..", "gatekit")
	if _, err := os.Stat(filepath.Join(src, "cmd", "gatekit")); err != nil {
		return "", nil, err
	}
	bin := filepath.Join(os.TempDir(), fmt.Sprintf("gatekit-contract-%d", os.Getpid()))
	build := exec.Command("go", "build", "-o", bin, "./cmd/gatekit")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		return "", nil, fmt.Errorf("build: %v: %s", err, out)
	}
	addr := freeAddr()
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "GATEKIT_LISTEN="+addr, "GATEKIT_METRICS_LISTEN="+freeAddr())
	if err := cmd.Start(); err != nil {
		return "", nil, err
	}
	stop := func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = os.Remove(bin) }
	url := "http://" + addr
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if resp, err := http.Get(url + "/readyz"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return url, stop, nil
			}
		}
	}
	stop()
	return "", nil, errors.New("gatekit never became ready")
}

func site(name string) *authv1.Site {
	host := name + ".dev.example.com"
	return &authv1.Site{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth"},
		Spec: authv1.SiteSpec{
			Hosts:    []string{host},
			Upstream: authv1.Upstream{Service: name, Namespace: name, Port: 8080},
			Gates: []authv1.Gate{
				{Name: "public", Match: authv1.Match{URL: "<https?>://" + host + "/<(health|docs)(/.*)?>", Methods: []string{"GET"}},
					Authenticators: []authv1.Handler{{Handler: "noop"}}, Authorizer: authv1.Handler{Handler: "allow"}},
				{Name: "browser", Match: authv1.Match{URL: "<https?>://" + host + "/<(?!(health|docs)(/.*)?$).*>", Methods: []string{"GET", "POST"}},
					Authenticators: []authv1.Handler{{Handler: "cookie_session"}},
					Authorizer: authv1.Handler{Handler: "remote_json", Config: &runtime.RawExtension{Raw: []byte(
						`{"remote":"http://opa-authz-proxy.auth:8080","payload":"{\"app\":\"` + name + `\"}"}`)}},
					Mutators: []authv1.Handler{{Handler: "header", Config: &runtime.RawExtension{Raw: []byte(`{"headers":{"X-User":"{{ print .Subject }}"}}`)}}},
					Errors:   []authv1.Handler{{Handler: "redirect", Config: &runtime.RawExtension{Raw: []byte(`{"to":"https://auth.dev.example.com/login"}`)}}}},
			},
		},
	}
}

func rules(s *authv1.Site) []render.OathkeeperRule {
	var out []render.OathkeeperRule
	for _, r := range render.Rules(s, config.Default()) {
		out = append(out, render.ToOathkeeper(r))
	}
	return out
}

func reason(err error) string {
	var ref *validate.Refusal
	if errors.As(err, &ref) {
		return ref.Reason
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return ""
}

func TestRealGatekitContract(t *testing.T) {
	g := validate.NewGatekit(baseURL)
	ctx := context.Background()

	// the operator's full rendered rules (lookahead carve-out, handler configs) are accepted
	if err := g.Validate(ctx, rules(site("shop")), rules(site("other"))); err != nil {
		t.Fatalf("rendered site refused: %v", err)
	}

	bad := site("typo")
	bad.Spec.Gates[0].Match.URL = "https://typo.dev.example.com/<(unclosed>"
	if got := reason(g.Validate(ctx, rules(bad), nil)); got != validate.ReasonPatternInvalid {
		t.Fatalf("invalid regex: got %q", got)
	}

	// a second site claiming the same URLs overlaps the first
	clash := site("shop")
	clash.Name = "clash"
	if got := reason(g.Validate(ctx, rules(clash), rules(site("shop")))); got != validate.ReasonRuleOverlap {
		t.Fatalf("overlap: got %q", got)
	}

	// overlap inside the candidate itself (two gates catching everything)
	dup := site("dup")
	dup.Spec.Gates[0].Match = authv1.Match{URL: "<https?>://dup.dev.example.com/<.*>", Methods: []string{"GET"}}
	dup.Spec.Gates[1].Match.URL = "<https?>://dup.dev.example.com/<.*>"
	if got := reason(g.Validate(ctx, rules(dup), nil)); got != validate.ReasonRuleOverlap {
		t.Fatalf("self overlap: got %q", got)
	}
}
