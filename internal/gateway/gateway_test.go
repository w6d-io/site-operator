package gateway

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/render"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func raw(s string) *runtime.RawExtension { return &runtime.RawExtension{Raw: []byte(s)} }

// platform is the dev/sandbox enabled set.
func platform() *authv1.GatewaySpec {
	return &authv1.GatewaySpec{
		Authenticators: map[string]authv1.GatewayHandler{
			"noop":           {Enabled: true},
			"cookie_session": {Enabled: true, Config: raw(`{"check_session_url":"http://kratos-public.auth/sessions/whoami","preserve_path":true}`)},
			"jwt":            {Enabled: false},
		},
		Authorizers: map[string]authv1.GatewayHandler{
			"allow":       {Enabled: true},
			"deny":        {Enabled: true},
			"remote_json": {Enabled: true, Config: raw(`{"remote":"http://opa-authz-proxy.auth:8080/v1/data/rbac/allow","payload":"{}"}`)},
		},
		Mutators: map[string]authv1.GatewayHandler{
			"noop":   {Enabled: true},
			"header": {Enabled: true, Config: raw(`{"headers":{"X-User":"{{ print .Subject }}"}}`)},
		},
		Errors: authv1.GatewayErrors{
			Handlers: map[string]authv1.GatewayHandler{
				"json":     {Enabled: true, Config: raw(`{"verbose":false}`)},
				"redirect": {Enabled: true, Config: raw(`{"to":"https://auth.dev.example.com/login"}`)},
			},
			Fallback: []string{"redirect", "json"},
		},
	}
}

func TestPlatformSpecIsValid(t *testing.T) {
	if p := Validate(platform()); len(p) != 0 {
		t.Fatalf("%v", p)
	}
}

func TestSchemaRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(*authv1.GatewaySpec)
		want   string
	}{
		"enabled without required config": {func(s *authv1.GatewaySpec) {
			s.Authenticators["cookie_session"] = authv1.GatewayHandler{Enabled: true}
		}, "authenticators.cookie_session"},
		"wrong type": {func(s *authv1.GatewaySpec) {
			s.Mutators["header"] = authv1.GatewayHandler{Enabled: true, Config: raw(`{"headers":{"X-User":42}}`)}
		}, "mutators.header.config.headers.X-User"},
		"unknown key": {func(s *authv1.GatewaySpec) {
			s.Authorizers["remote_json"] = authv1.GatewayHandler{Enabled: true, Config: raw(`{"remote":"http://x.auth/","payload":"{}","nope":1}`)}
		}, "authorizers.remote_json.config"},
		"not a uri": {func(s *authv1.GatewaySpec) {
			s.Authenticators["cookie_session"] = authv1.GatewayHandler{Enabled: true, Config: raw(`{"check_session_url":"not a url"}`)}
		}, "authenticators.cookie_session.config.check_session_url"},
		"config on a handler without config": {func(s *authv1.GatewaySpec) {
			s.Authorizers["allow"] = authv1.GatewayHandler{Enabled: true, Config: raw(`{"x":1}`)}
		}, "authorizers.allow"},
		"fallback not enabled": {func(s *authv1.GatewaySpec) {
			s.Errors.Fallback = []string{"www_authenticate"}
		}, "errors.fallback: www_authenticate is not an enabled error handler"},
		"default fallback json disabled": {func(s *authv1.GatewaySpec) {
			s.Errors.Fallback = nil
			delete(s.Errors.Handlers, "json")
		}, "errors.fallback: json"},
		"secret": {func(s *authv1.GatewaySpec) {
			s.Authenticators["oauth2_introspection"] = authv1.GatewayHandler{Enabled: true, Config: raw(
				`{"introspection_url":"http://hydra-admin.auth:4445/admin/oauth2/introspect","pre_authorization":{"enabled":true,"client_id":"a","client_secret":"s","token_url":"http://hydra.auth/oauth2/token"}}`)}
		}, `"client_secret" looks like a secret`},
		"vault reference": {func(s *authv1.GatewaySpec) {
			s.Authorizers["remote_json"] = authv1.GatewayHandler{Enabled: true, Config: raw(
				`{"remote":"http://opa-authz-proxy.auth:8080/","payload":"{}","headers":{"Authorization":"vault:secret/opa#token"}}`)}
		}, "secret references are not resolved"},
		"unknown handler": {func(s *authv1.GatewaySpec) {
			s.Mutators["teleport"] = authv1.GatewayHandler{Enabled: true}
		}, "mutators.teleport: unknown handler"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := platform()
			tc.mutate(s)
			p := Validate(s)
			if !strings.Contains(strings.Join(p, "\n"), tc.want) {
				t.Fatalf("want %q in %v", tc.want, p)
			}
		})
	}
}

const base = `
log: {level: info, format: json}
serve:
  proxy: {port: 4455, trust_forwarded_headers: true}
  api: {port: 4456}
access_rules:
  matching_strategy: regexp
  repositories: [file:///etc/rules/access-rules.json]
authenticators:
  anonymous: {enabled: true, config: {subject: guest}}
`

func TestRenderKeepsBaseAndOwnsHandlers(t *testing.T) {
	out, hash, err := Render([]byte(base), platform())
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	serve := cfg["serve"].(map[string]any)["proxy"].(map[string]any)
	if serve["trust_forwarded_headers"] != true || cfg["access_rules"].(map[string]any)["matching_strategy"] != "regexp" ||
		cfg["log"].(map[string]any)["level"] != "info" {
		t.Fatalf("base keys changed: %s", out)
	}
	authn := cfg["authenticators"].(map[string]any)
	if authn["anonymous"].(map[string]any)["enabled"] != false {
		t.Fatalf("a handler the Gateway leaves out must be disabled, whatever the base says")
	}
	if len(authn) != len(authv1.GatewayHandlers[authv1.KindAuthenticators]) {
		t.Fatalf("every authenticator is listed: %v", authn)
	}
	if authn["cookie_session"].(map[string]any)["config"].(map[string]any)["check_session_url"] != "http://kratos-public.auth/sessions/whoami" {
		t.Fatalf("config not rendered: %v", authn["cookie_session"])
	}
	errs := cfg["errors"].(map[string]any)
	if f := errs["fallback"].([]any); len(f) != 2 || f[0] != "redirect" {
		t.Fatalf("fallback %v", f)
	}
	again, hash2, _ := Render([]byte(base), platform())
	if hash2 != hash || string(again) != string(out) || len(hash) != 8 {
		t.Fatalf("render not deterministic")
	}
	s := platform()
	s.Mutators["header"] = authv1.GatewayHandler{Enabled: true, Config: raw(`{"headers":{"X-User":"{{ print .Extra.email }}"}}`)}
	if _, h, _ := Render([]byte(base), s); h == hash {
		t.Fatal("a config change must change the hash")
	}
}

func TestInUseAndDisabled(t *testing.T) {
	rule := func(name, site, authn string, retired bool) okv1.Rule {
		r := okv1.Rule{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth", Labels: map[string]string{}},
			Spec: okv1.RuleSpec{Match: &okv1.Match{URL: "https://x/", Methods: []string{"GET"}},
				Authenticators: []*okv1.Handler{{Handler: authn}}, Authorizer: &okv1.Handler{Handler: "allow"}}}
		if site != "" {
			r.Labels[render.SiteLabel] = site
		}
		if retired {
			render.Retire(&r)
		}
		return r
	}
	uses := InUse([]okv1.Rule{
		rule("shop-browser-1", "shop", "cookie_session", false),
		rule("blog-api-1", "blog", "jwt", false),
		rule("platform-health", "", "jwt", false),
		rule("old-api-1", "old", "anonymous", true), // retired: matches nothing
	})
	got := map[string]string{}
	for _, u := range uses {
		got[u.Handler] = strings.Join(u.UsedBy, ",")
	}
	if got["authenticators/jwt"] != "blog,rule/platform-health" || got["authenticators/cookie_session"] != "shop" ||
		got["authorizers/allow"] != "blog,rule/platform-health,shop" || got["mutators/noop"] == "" || got["authenticators/anonymous"] != "" {
		t.Fatalf("%v", got)
	}
	d := Disabled(platform(), uses)
	if len(d) != 1 || d[0] != "authenticators/jwt (used by blog, rule/platform-health)" {
		t.Fatalf("%v", d)
	}
}
