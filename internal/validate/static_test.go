package validate

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
)

var zones = []authv1.Zone{
	{ObjectMeta: metav1.ObjectMeta{Name: "dev"}, Spec: authv1.ZoneSpec{Domain: "dev.example.com", TLS: authv1.ZoneTLS{Mode: authv1.ZoneTLSDefault}}},
	{ObjectMeta: metav1.ObjectMeta{Name: "sandbox"}, Spec: authv1.ZoneSpec{Domain: "authdev.dev.example.com", TLS: authv1.ZoneTLS{Mode: authv1.ZoneTLSIssuer}}},
}

func payload(app string) *runtime.RawExtension {
	return &runtime.RawExtension{Raw: []byte(`{"remote":"http://opa-authz-proxy.auth:8080","payload":"{\"input\": {\"sub\":\"{{ print .Subject }}\", \"app\": \"` + app + `\"}}"}`)}
}

func site() *authv1.Site {
	return &authv1.Site{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "auth"},
		Spec: authv1.SiteSpec{
			Hosts:    []string{"shop.dev.example.com"},
			Upstream: authv1.Upstream{Service: "shop", Namespace: "shop", Port: 8080},
			Gates: []authv1.Gate{{
				Name:           "main",
				Match:          authv1.Match{URL: "<https?>://shop.dev.example.com/<.*>", Methods: []string{"GET"}},
				Authenticators: []authv1.Handler{{Handler: "cookie_session"}},
				Authorizer:     authv1.Handler{Handler: "remote_json", Config: payload("shop")},
				Mutators:       []authv1.Handler{{Handler: "header"}},
				Errors:         []authv1.Handler{{Handler: "redirect"}},
			}},
		},
	}
}

func TestStatic(t *testing.T) {
	cfg := config.Default()
	cfg.ReservedHosts = []string{"auth.dev.example.com"}
	onAuthHost := func(s *authv1.Site) {
		s.Spec.Hosts = []string{"auth.dev.example.com"}
		s.Spec.Gates[0].Match.URL = "https://auth.dev.example.com/<.*>"
	}
	cases := []struct {
		name   string
		mutate func(*authv1.Site)
		reason string
	}{
		{"valid", func(*authv1.Site) {}, ""},
		{"other namespace", func(s *authv1.Site) { s.Namespace = "default" }, ReasonWrongNamespace},
		{"foreign domain", func(s *authv1.Site) { s.Spec.Hosts = []string{"evil.example.com"} }, ReasonHostNotInZone},
		{"two labels under a zone", func(s *authv1.Site) { s.Spec.Hosts = []string{"a.b.dev.example.com"} }, ReasonHostNotInZone},
		{"zone apex", func(s *authv1.Site) { s.Spec.Hosts = []string{"dev.example.com"} }, ReasonHostNotInZone},
		{"suffix trick", func(s *authv1.Site) { s.Spec.Hosts = []string{"x.dev.example.com.evil.io"} }, ReasonHostNotInZone},
		{"nested zone", func(s *authv1.Site) {
			s.Spec.Hosts = []string{"shop.authdev.dev.example.com"}
			s.Spec.Gates[0].Match.URL = "https://shop.authdev.dev.example.com/<.*>"
		}, ""},
		{"reserved host", onAuthHost, ReasonHostReserved},
		{"ambiguous error handlers", func(s *authv1.Site) {
			s.Spec.Gates[0].Errors = []authv1.Handler{
				{Handler: "redirect", Config: &runtime.RawExtension{Raw: []byte(`{"to":"https://x/","when":[{"error":["forbidden"],"request":{"header":{"accept":["text/html"]}}}]}`)}},
				{Handler: "json"}, // inherits the gateway's when: also answers browsers' 403
			}
		}, ReasonErrorsAmbiguous},
		{"disjoint error handlers", func(s *authv1.Site) {
			s.Spec.Gates[0].Errors = []authv1.Handler{
				{Handler: "redirect", Config: &runtime.RawExtension{Raw: []byte(`{"to":"https://x/","when":[{"error":["forbidden"],"request":{"header":{"accept":["text/html"]}}}]}`)}},
				{Handler: "json", Config: &runtime.RawExtension{Raw: []byte(`{"when":[{"error":["unauthorized","not_found","internal_server_error"]},{"error":["forbidden"],"request":{"header":{"accept":["application/json"]}}}]}`)}},
			}
		}, ""},
		{"reserved host system", func(s *authv1.Site) { onAuthHost(s); s.Spec.System = true }, ""},
		{"pattern for another host", func(s *authv1.Site) {
			s.Spec.Gates[0].Match.URL = "<https?>://auth.dev.example.com/<.*>"
		}, ReasonPatternHostMismatch},
		{"pattern host prefix trick", func(s *authv1.Site) {
			s.Spec.Gates[0].Match.URL = "<https?>://shop.dev.example.com<.*>"
		}, ReasonPatternHostMismatch},
		{"regex host", func(s *authv1.Site) { s.Spec.Gates[0].Match.URL = "<.*>/x" }, ReasonPatternHostMismatch},
		{"kratos admin", func(s *authv1.Site) {
			s.Spec.Upstream = authv1.Upstream{Service: "auth-kratos-admin", Namespace: "auth", Port: 80}
		}, ReasonUpstreamNotAllowed},
		{"opal port", func(s *authv1.Site) {
			s.Spec.Upstream = authv1.Upstream{Service: "policy", Namespace: "auth", Port: 8181}
		}, ReasonUpstreamNotAllowed},
		{"redis", func(s *authv1.Site) {
			s.Spec.Upstream = authv1.Upstream{Service: "jinbe-redis", Namespace: "auth", Port: 80}
		}, ReasonUpstreamNotAllowed},
		{"gate upstream override", func(s *authv1.Site) {
			s.Spec.Gates[0].Upstream = &authv1.Upstream{Service: "auth-postgresql", Namespace: "auth", Port: 5432}
		}, ReasonUpstreamNotAllowed},
		{"disabled authenticator", func(s *authv1.Site) {
			s.Spec.Gates[0].Authenticators = []authv1.Handler{{Handler: "jwt"}}
		}, ReasonHandlerNotEnabled},
		{"disabled mutator", func(s *authv1.Site) {
			s.Spec.Gates[0].Mutators = []authv1.Handler{{Handler: "id_token"}}
		}, ReasonHandlerNotEnabled},
		{"disabled error handler", func(s *authv1.Site) {
			s.Spec.Gates[0].Errors = []authv1.Handler{{Handler: "www_authenticate"}}
		}, ReasonHandlerNotEnabled},
		{"app not pinned", func(s *authv1.Site) { s.Spec.Gates[0].Authorizer.Config = payload("other") }, ReasonAppNotPinned},
		{"no payload", func(s *authv1.Site) { s.Spec.Gates[0].Authorizer.Config = nil }, ReasonAppNotPinned},
		{"allow needs no pin", func(s *authv1.Site) { s.Spec.Gates[0].Authorizer = authv1.Handler{Handler: "allow"} }, ""},
		{"vanity class", func(s *authv1.Site) {
			s.Spec.Exposure = authv1.Exposure{Mode: authv1.ExposureVanity, IngressClass: "eg"}
		}, ReasonIngressClass},
		{"vanity issuer", func(s *authv1.Site) {
			s.Spec.Exposure = authv1.Exposure{Mode: authv1.ExposureVanity, TLS: authv1.TLSPerSite, Issuer: "self-signed"}
		}, ReasonIssuer},
		{"vanity per-site ok", func(s *authv1.Site) {
			s.Spec.Exposure = authv1.Exposure{Mode: authv1.ExposureVanity, TLS: authv1.TLSPerSite}
		}, ""},
		{"vanity default cert ok", func(s *authv1.Site) { s.Spec.Exposure = authv1.Exposure{Mode: authv1.ExposureVanity} }, ""},
		{"vanity default cert in issuer zone", func(s *authv1.Site) {
			s.Spec.Hosts = []string{"shop.authdev.dev.example.com"}
			s.Spec.Gates[0].Match.URL = "https://shop.authdev.dev.example.com/<.*>"
			s.Spec.Exposure = authv1.Exposure{Mode: authv1.ExposureVanity}
		}, ReasonNotCoveredByWildcard},
		{"no ingress skips exposure", func(s *authv1.Site) { s.Spec.Exposure = authv1.Exposure{IngressClass: "eg"} }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := site()
			tc.mutate(s)
			got := Static(s, cfg, zones)
			switch {
			case tc.reason == "" && got != nil:
				t.Fatalf("unexpected refusal %v", got)
			case tc.reason != "" && (got == nil || got.Reason != tc.reason):
				t.Fatalf("want %s, got %v", tc.reason, got)
			}
		})
	}
}

func TestNoZoneNoSite(t *testing.T) {
	if got := Static(site(), config.Default(), nil); got == nil || got.Reason != ReasonHostNotInZone {
		t.Fatalf("a site with no Zone defined must be refused, got %v", got)
	}
}

func TestHostsUnderAZoneNotOwned(t *testing.T) {
	cfg := config.Default()
	sandbox := func(s *authv1.Site) { s.Spec.Hosts = []string{"shop.authdev.dev.example.com"} }
	cases := []struct {
		name   string
		zones  []string
		mutate func(*authv1.Site)
		reason string
	}{
		{"no --zones owns every zone", nil, func(*authv1.Site) {}, ""},
		{"owned zone", []string{"dev"}, func(*authv1.Site) {}, ""},
		{"zone of another release", []string{"sandbox"}, func(*authv1.Site) {}, ReasonZoneNotOwned},
		{"nested zone owned, parent not", []string{"sandbox"}, sandbox, ""},
		{"parent owned, nested zone not", []string{"dev"}, sandbox, ReasonZoneNotOwned},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg.Zones = c.zones
			s := site()
			c.mutate(s)
			ref := Hosts(s, cfg, zones)
			switch {
			case c.reason == "" && ref != nil:
				t.Fatalf("unexpected refusal %v", ref)
			case c.reason != "" && (ref == nil || ref.Reason != c.reason):
				t.Fatalf("want %s, got %v", c.reason, ref)
			}
		})
	}
}
