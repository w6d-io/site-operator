// Package validate refuses Sites that must never reach the gateway: static checks
// against the operator config, then pattern compile + overlap checks via gatekit.
package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
	"github.com/w6d-io/site-operator/internal/render"
)

// Condition reasons for Validated=False.
const (
	ReasonWrongNamespace       = "WrongNamespace"
	ReasonHostNotInZone        = "HostNotInZone"
	ReasonHandlerNotEnabled    = "HandlerNotEnabled"
	ReasonAppNotPinned         = "AppNotPinned"
	ReasonHostReserved         = "HostReserved"
	ReasonPatternHostMismatch  = "PatternHostMismatch"
	ReasonUpstreamNotAllowed   = "UpstreamNotAllowed"
	ReasonIngressClass         = "IngressClassNotAllowed"
	ReasonIssuer               = "IssuerNotAllowed"
	ReasonCertificatesDisabled = "CertificatesDisabled"
	ReasonNotCoveredByWildcard = "NotCoveredByWildcard"
	ReasonPatternInvalid       = "PatternInvalid"
	ReasonRuleOverlap          = "RuleOverlap"
	ReasonValidatorUnavailable = "ValidatorUnavailable"
)

// Refusal is a definitive "this Site is invalid" answer (as opposed to an
// infrastructure error such as gatekit being unreachable).
type Refusal struct {
	Reason  string
	Message string
}

func (r *Refusal) Error() string { return r.Reason + ": " + r.Message }

func refuse(reason, format string, a ...any) *Refusal {
	return &Refusal{Reason: reason, Message: fmt.Sprintf(format, a...)}
}

// Validator re-checks rendered rules with the real Oathkeeper matcher.
// It returns a *Refusal for invalid rules and any other error when it cannot decide.
type Validator interface {
	Validate(ctx context.Context, candidate, others []render.OathkeeperRule) error
}

var label = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// schemePrefixes are the only accepted starts of a match URL; the host that
// follows must be literal so a Site can only claim its own hosts.
var schemePrefixes = []string{"https://", "http://", "<https?>://", "<http|https>://", "<(http|https)>://"}

// HostZone returns the Zone whose wildcard covers host (exactly one label under
// its domain), or nil.
func HostZone(host string, zones []authv1.Zone) *authv1.Zone {
	for i := range zones {
		if prefix, ok := strings.CutSuffix(host, "."+zones[i].Spec.Domain); ok && label.MatchString(prefix) {
			return &zones[i]
		}
	}
	return nil
}

// UpstreamAllowed applies the allow and deny regexes to a rendered upstream URL.
func UpstreamAllowed(url string, cfg *config.Config) bool {
	return cfg.AllowedUpstream.MatchString(url) && !cfg.DeniedUpstream.MatchString(url)
}

// Hosts checks what a Site may claim at all: its namespace and hosts. It is all
// a paused Site needs (its deny Rules are fixed and need no gatekit check).
func Hosts(site *authv1.Site, cfg *config.Config, zones []authv1.Zone) *Refusal {
	if site.Namespace != cfg.GatewayNamespace {
		return refuse(ReasonWrongNamespace, "sites must live in the gateway namespace %q", cfg.GatewayNamespace)
	}
	for _, h := range site.Spec.Hosts {
		if HostZone(h, zones) == nil {
			return refuse(ReasonHostNotInZone, "host %q is not one label under a Zone domain", h)
		}
		if !site.Spec.System && slices.Contains(cfg.ReservedHosts, h) {
			return refuse(ReasonHostReserved, "host %q is reserved for system sites", h)
		}
	}
	return nil
}

// Static checks a Site against the operator config and the Zones. It needs no network.
func Static(site *authv1.Site, cfg *config.Config, zones []authv1.Zone) *Refusal {
	if ref := Hosts(site, cfg, zones); ref != nil {
		return ref
	}
	for i, u := range render.Upstreams(site) {
		if url := render.UpstreamURL(u); !UpstreamAllowed(url, cfg) {
			return refuse(ReasonUpstreamNotAllowed, "gate %q: upstream %q is not allowed", site.Spec.Gates[i].Name, url)
		}
	}
	for _, g := range site.Spec.Gates {
		if !matchHostOK(g.Match.URL, site.Spec.Hosts) {
			return refuse(ReasonPatternHostMismatch, "gate %q: match url must start with a scheme and one of the site hosts followed by /", g.Name)
		}
		if ref := handlersEnabled(g, cfg); ref != nil {
			return ref
		}
		if g.Authorizer.Handler == "remote_json" && !appPinned(g.Authorizer, site.Name) {
			return refuse(ReasonAppNotPinned, "gate %q: the remote_json payload must pin \"app\":%q", g.Name, site.Name)
		}
	}
	return exposure(site, cfg, zones)
}

func handlersEnabled(g authv1.Gate, cfg *config.Config) *Refusal {
	check := func(stage string, hs []authv1.Handler, enabled []string) *Refusal {
		for _, h := range hs {
			if !slices.Contains(enabled, h.Handler) {
				return refuse(ReasonHandlerNotEnabled, "gate %q: %s %q is not enabled on the gateway", g.Name, stage, h.Handler)
			}
		}
		return nil
	}
	for _, c := range []struct {
		stage   string
		hs      []authv1.Handler
		enabled []string
	}{
		{"authenticator", g.Authenticators, cfg.EnabledAuthenticators},
		{"authorizer", []authv1.Handler{g.Authorizer}, cfg.EnabledAuthorizers},
		{"mutator", g.Mutators, cfg.EnabledMutators},
		{"error handler", g.Errors, cfg.EnabledErrors},
	} {
		if ref := check(c.stage, c.hs, c.enabled); ref != nil {
			return ref
		}
	}
	return nil
}

// appPinned reports whether the remote_json payload names the site as "app", so
// the policy never scans every route of every service (26x slower).
func appPinned(h authv1.Handler, app string) bool {
	if h.Config == nil {
		return false
	}
	var cfg struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(h.Config.Raw, &cfg); err != nil {
		return false
	}
	compact := strings.Join(strings.Fields(cfg.Payload), "")
	return strings.Contains(compact, `"app":"`+app+`"`)
}

func exposure(site *authv1.Site, cfg *config.Config, zones []authv1.Zone) *Refusal {
	e := site.Spec.Exposure
	if !e.Vanity() {
		return nil
	}
	if cls := render.IngressClass(site, cfg); !slices.Contains(cfg.IngressClasses, cls) {
		return refuse(ReasonIngressClass, "ingress class %q is not allowed", cls)
	}
	if e.TLS == authv1.TLSPerSite {
		if !cfg.EnableCertificates {
			return refuse(ReasonCertificatesDisabled, "per-site certificates are disabled on this operator")
		}
		if iss := render.Issuer(site, cfg); !slices.Contains(cfg.Issuers, iss) {
			return refuse(ReasonIssuer, "issuer %q is not allowed", iss)
		}
		return nil
	}
	// a vanity Ingress without its own certificate gets the controller default one
	for _, h := range site.Spec.Hosts {
		if z := HostZone(h, zones); z.Spec.TLS.Mode != authv1.ZoneTLSDefault && z.Spec.TLS.Mode != "" {
			return refuse(ReasonNotCoveredByWildcard, "host %q: zone %q does not use the default certificate; use tls: per-site", h, z.Name)
		}
	}
	return nil
}

func matchHostOK(url string, hosts []string) bool {
	for _, p := range schemePrefixes {
		rest, ok := strings.CutPrefix(url, p)
		if !ok {
			continue
		}
		for _, h := range hosts {
			if strings.HasPrefix(rest, h+"/") {
				return true
			}
		}
	}
	return false
}
