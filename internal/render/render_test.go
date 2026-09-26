package render

import (
	"encoding/json"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
)

func testSite() *authv1.Site {
	return &authv1.Site{
		ObjectMeta: metav1.ObjectMeta{Name: "payroll", Namespace: "auth", UID: "uid-1", Generation: 3},
		Spec: authv1.SiteSpec{
			Hosts:    []string{"payroll.dev.example.com"},
			Upstream: authv1.Upstream{Service: "payroll", Namespace: "payroll", Port: 8080},
			Gates: []authv1.Gate{
				{
					Name:           "public",
					Match:          authv1.Match{URL: "<https?>://payroll.dev.example.com/<(health|docs)(/.*)?>", Methods: []string{"GET"}},
					Authenticators: []authv1.Handler{{Handler: "noop"}},
					Authorizer:     authv1.Handler{Handler: "allow"},
					Mutators:       []authv1.Handler{{Handler: "noop"}},
				},
				{
					Name:           "browser",
					Match:          authv1.Match{URL: "<https?>://payroll.dev.example.com/<(?!(health|docs)(/.*)?$).*>", Methods: []string{"GET", "POST"}},
					Authenticators: []authv1.Handler{{Handler: "cookie_session"}},
					Authorizer:     authv1.Handler{Handler: "remote_json"},
					Mutators:       []authv1.Handler{{Handler: "header", Config: raw(`{"headers":{"X-User":"{{ print .Subject }}"}}`)}},
					Errors:         []authv1.Handler{{Handler: "redirect"}},
					Upstream:       &authv1.Upstream{Service: "payroll-web", Namespace: "payroll", Port: 3000, PreserveHost: true},
				},
			},
			Exposure: authv1.Exposure{Mode: authv1.ExposureVanity, TLS: authv1.TLSWildcard},
		},
	}
}

func raw(s string) *runtime.RawExtension { return &runtime.RawExtension{Raw: []byte(s)} }

func TestRulesAreNamedByContentAndOwned(t *testing.T) {
	cfg := config.Default()
	rules := Rules(testSite(), cfg)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}
	for _, r := range rules {
		if !strings.HasPrefix(r.Name, "payroll-") || len(r.Name) != len("payroll-")+len(strings.Split(r.Name, "-")[1])+1+8 {
			t.Errorf("bad name %q", r.Name)
		}
		if r.Namespace != "auth" || r.Labels[SiteLabel] != "payroll" || r.Annotations[SpecHashAnnotation] == "" {
			t.Errorf("missing meta on %s: %+v", r.Name, r.ObjectMeta)
		}
		if len(r.OwnerReferences) != 1 || r.OwnerReferences[0].UID != "uid-1" || !*r.OwnerReferences[0].Controller {
			t.Errorf("owner ref missing on %s", r.Name)
		}
		if r.Spec.ConfigMapName != nil {
			t.Errorf("configMapName must be unset in sidecar mode")
		}
		if r.Labels[GateLabel] == "" {
			t.Errorf("gate label missing on %s", r.Name)
		}
	}
	if got := rules[1].Spec.Upstream.URL; got != "http://payroll-web.payroll.svc.cluster.local:3000" {
		t.Errorf("gate upstream override not applied: %s", got)
	}
	if got := rules[0].Spec.Upstream.URL; got != "http://payroll.payroll.svc.cluster.local:8080" {
		t.Errorf("site upstream not applied: %s", got)
	}
}

func TestRuleNameChangesWithMutatorTemplate(t *testing.T) {
	cfg := config.Default()
	s := testSite()
	before := Rules(s, cfg)
	s.Spec.Gates[1].Mutators[0].Config = raw(`{"headers":{"X-User":"{{ print .Extra.email }}"}}`)
	after := Rules(s, cfg)
	if before[0].Name != after[0].Name {
		t.Errorf("untouched gate renamed: %s -> %s", before[0].Name, after[0].Name)
	}
	if before[1].Name == after[1].Name {
		t.Errorf("template change must rename the rule, still %s", after[1].Name)
	}
	// deterministic: same input, same names
	again := Rules(s, cfg)
	if again[1].Name != after[1].Name {
		t.Errorf("render not deterministic")
	}
	s.Spec.Gates[1].Authorizer.Config = raw(`{"remote":"http://opa-authz-proxy.auth:8080/v1/data/rbac/allow","payload":"{\"app\":\"payroll2\"}"}`)
	if Rules(s, cfg)[1].Name == after[1].Name {
		t.Errorf("an authorizer payload is a template too: the rule must be renamed")
	}
}

// Changes Oathkeeper does not cache by rule id keep the Rule name, so the Rule
// is updated in place: one maester write, no window without (or with two) rules.
func TestRuleNameStableWithoutTemplateChange(t *testing.T) {
	cfg := config.Default()
	s := testSite()
	before := Rules(s, cfg)
	s.Spec.Gates[1].Match.URL = "<https?>://payroll.dev.example.com/<(?!(health|docs|metrics)(/.*)?$).*>"
	s.Spec.Gates[1].Match.Methods = []string{"GET"}
	s.Spec.Gates[1].Authenticators = []authv1.Handler{{Handler: "bearer_token"}}
	s.Spec.Gates[1].Errors = []authv1.Handler{{Handler: "json"}}
	s.Spec.Upstream.Port = 9090
	after := Rules(s, cfg)
	for i := range before {
		if before[i].Name != after[i].Name {
			t.Errorf("gate %d renamed without a template change: %s -> %s", i, before[i].Name, after[i].Name)
		}
	}
	if before[1].Annotations[SpecHashAnnotation] == after[1].Annotations[SpecHashAnnotation] {
		t.Errorf("the spec hash must still follow the whole spec (drift detection)")
	}
}

func TestRuleConfigMapNameFromConfig(t *testing.T) {
	cfg := config.Default()
	cfg.RulesConfigMap = "oathkeeper-rules"
	for _, r := range Rules(testSite(), cfg) {
		if r.Spec.ConfigMapName == nil || *r.Spec.ConfigMapName != "oathkeeper-rules" {
			t.Fatalf("configMapName not set")
		}
	}
}

func TestIngressIsFixedTemplate(t *testing.T) {
	cfg := config.Default()
	cfg.IngressAnnotations = map[string]string{"nginx.ingress.kubernetes.io/proxy-read-timeout": "300"}
	ing := Ingress(testSite(), cfg)
	if ing.Name != "site-payroll" || ing.Namespace != "auth" {
		t.Fatalf("bad name %s/%s", ing.Namespace, ing.Name)
	}
	if *ing.Spec.IngressClassName != "nginx" {
		t.Errorf("default class not applied")
	}
	if ing.Spec.DefaultBackend != nil {
		t.Errorf("default backend must never be set")
	}
	for _, r := range ing.Spec.Rules {
		for _, p := range r.HTTP.Paths {
			if p.Backend.Service.Name != "auth-oathkeeper-proxy" || p.Backend.Service.Port.Name != "http" || p.Path != "/" {
				t.Errorf("backend not pinned: %+v", p)
			}
		}
	}
	if len(ing.Spec.TLS) != 0 {
		t.Errorf("wildcard mode must not carry a tls block")
	}
	if ing.Annotations["nginx.ingress.kubernetes.io/proxy-read-timeout"] != "300" || len(ing.Annotations) != 2 {
		t.Errorf("annotations = config set + spec hash, got %v", ing.Annotations)
	}
	if len(ing.OwnerReferences) != 1 {
		t.Errorf("owner ref missing")
	}
}

func TestPerSiteTLSRendersCertificate(t *testing.T) {
	cfg := config.Default()
	s := testSite()
	s.Spec.Exposure.TLS = authv1.TLSPerSite
	ing := Ingress(s, cfg)
	if len(ing.Spec.TLS) != 1 || ing.Spec.TLS[0].SecretName != "site-payroll-tls" {
		t.Fatalf("per-site tls block missing: %+v", ing.Spec.TLS)
	}
	c := Certificate(s, cfg)
	spec := c.Object["spec"].(map[string]any)
	if c.GetName() != "site-payroll" || spec["secretName"] != "site-payroll-tls" {
		t.Errorf("bad certificate %v", c.Object)
	}
	ref := spec["issuerRef"].(map[string]any)
	if ref["name"] != "letsencrypt-prod" || ref["kind"] != "ClusterIssuer" {
		t.Errorf("bad issuer %v", ref)
	}
	if c.GetAnnotations()[SpecHashAnnotation] == "" || len(c.GetOwnerReferences()) != 1 {
		t.Errorf("certificate meta incomplete")
	}
}

func TestOathkeeperJSON(t *testing.T) {
	r := Rules(testSite(), config.Default())[1]
	b, err := json.Marshal(ToOathkeeper(r))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{`"id":"` + r.Name + `.auth"`, `"preserve_host":true`, `"handler":"redirect"`, `"X-User"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
}

func TestUpstreamURL(t *testing.T) {
	if got := UpstreamURL(authv1.Upstream{Service: "a", Namespace: "b", Port: 443, Scheme: "https"}); got != "https://a.b.svc.cluster.local:443" {
		t.Fatal(got)
	}
	cfg := config.Default()
	for _, u := range []authv1.Upstream{
		{Service: "auth-kratos-admin", Namespace: "auth", Port: 80},
		{Service: "opa", Namespace: "auth", Port: 80},
		{Service: "auth-opal-client", Namespace: "auth", Port: 7000},
		{Service: "jinbe-redis", Namespace: "auth", Port: 80},
		{Service: "x", Namespace: "db", Port: 5432},
	} {
		if url := UpstreamURL(u); !cfg.DeniedUpstream.MatchString(url) {
			t.Errorf("%s not denied", url)
		}
	}
	if url := UpstreamURL(authv1.Upstream{Service: "shop", Namespace: "shop", Port: 8080}); !cfg.AllowedUpstream.MatchString(url) || cfg.DeniedUpstream.MatchString(url) {
		t.Errorf("%s refused", url)
	}
}

func TestRetire(t *testing.T) {
	r := Rules(testSite(), config.Default())[0]
	Retire(r)
	if !Retired(r) || r.Spec.Match.URL != "https://"+r.Name+".retired.invalid/" {
		t.Fatalf("not retired: %+v", r.Spec.Match)
	}
}

func TestZoneIngressAndCertificate(t *testing.T) {
	cfg := config.Default()
	z := &authv1.Zone{ObjectMeta: metav1.ObjectMeta{Name: "dev", UID: "z1"},
		Spec: authv1.ZoneSpec{Domain: "dev.example.com", TLS: authv1.ZoneTLS{Mode: authv1.ZoneTLSDefault}}}
	ing := ZoneIngress(z, cfg)
	if ing.Name != "zone-dev" || ing.Namespace != "auth" || ing.Spec.Rules[0].Host != "*.dev.example.com" || len(ing.Spec.TLS) != 0 {
		t.Fatalf("bad zone ingress %+v", ing)
	}
	if ing.OwnerReferences[0].Kind != "Zone" || ing.Labels[ZoneLabel] != "dev" {
		t.Fatalf("bad owner %+v", ing.ObjectMeta)
	}
	z.Spec.TLS = authv1.ZoneTLS{Mode: authv1.ZoneTLSIssuer}
	ing = ZoneIngress(z, cfg)
	if ing.Spec.TLS[0].SecretName != "zone-dev-tls" {
		t.Fatalf("tls %+v", ing.Spec.TLS)
	}
	c := ZoneCertificate(z, cfg)
	dns, _, _ := unstructured.NestedStringSlice(c.Object, "spec", "dnsNames")
	if c.GetNamespace() != "auth" || len(dns) != 1 || dns[0] != "*.dev.example.com" {
		t.Fatalf("cert %v", c.Object)
	}
	z.Spec.TLS = authv1.ZoneTLS{Mode: authv1.ZoneTLSSecret, SecretName: "example-com-tls"}
	if ZoneIngress(z, cfg).Spec.TLS[0].SecretName != "example-com-tls" {
		t.Fatal("secret mode")
	}
}

func TestPausedRules(t *testing.T) {
	cfg := config.Default()
	s := testSite()
	s.Spec.Hosts = append(s.Spec.Hosts, "pay.dev.example.com")
	rs := PausedRules(s, cfg)
	if len(rs) != 2 || rs[1].Labels[GateLabel] != "paused-1" || rs[0].Spec.Authorizer.Handler != "deny" {
		t.Fatalf("one deny rule per host expected: %+v", rs)
	}
	if len(rs[0].Spec.Errors) != 1 || rs[0].Spec.Errors[0].Handler != "json" {
		t.Fatalf("json only without a paused page: %+v", rs[0].Spec.Errors)
	}
	cfg.PausedRedirectURL = "https://auth.dev.example.com/paused"
	rs = PausedRules(s, cfg)
	b, _ := json.Marshal(rs[0].Spec.Errors)
	for _, want := range []string{`"handler":"redirect"`, `paused?site=payroll`, `"text/html"`, `"forbidden"`, `"handler":"json"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
}
