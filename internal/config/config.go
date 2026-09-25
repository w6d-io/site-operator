// Package config holds the operator settings. None of them can be set from a
// Site: they are the platform's fixed template inputs.
package config

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Config is the operator configuration (flags, each with an env fallback).
type Config struct {
	// GatewayNamespace is where Sites, Rules and Ingresses live (Ingress backends are same-namespace only).
	GatewayNamespace string
	// GatewayService / GatewayServicePort is the oathkeeper-proxy Service every Ingress points at.
	GatewayService     string
	GatewayServicePort string
	// ReservedHosts can only be used by system sites.
	ReservedHosts []string
	// IngressClasses allowed on Sites and Zones; the first one is the default.
	IngressClasses []string
	// IngressAnnotations are stamped on every rendered Ingress (values fixed here, never from a Site).
	IngressAnnotations map[string]string
	// Issuers allowed for Certificates; the first one is the default.
	Issuers []string
	// AllowedUpstream / DeniedUpstream bound every rendered rule upstream URL.
	AllowedUpstream *regexp.Regexp
	DeniedUpstream  *regexp.Regexp
	// Enabled handlers per pipeline stage: the gateway drops rules naming others.
	EnabledAuthenticators, EnabledAuthorizers, EnabledMutators, EnabledErrors []string
	// RulesConfigMap, when set, is written into every Rule (maester controller mode).
	RulesConfigMap string
	// ZonesConfigMap is the ConfigMap (gateway namespace) the operator mirrors Zone
	// domains into, for the admission policy.
	ZonesConfigMap string
	// PausedRedirectURL, when set, is where browsers hitting a paused Site are
	// sent (?site=<name> is appended); JSON clients always get the json error.
	PausedRedirectURL string
	// GatekitURL is the gatekit base URL used to re-validate patterns and overlaps.
	GatekitURL string
	// EnableCertificates watches/writes cert-manager Certificates (needs the CRD).
	EnableCertificates bool
}

// Defaults for the dev environment; overridden per env by flags.
const (
	DefaultAllowedUpstream = `^https?://[a-z]([a-z0-9-]*[a-z0-9])?\.[a-z0-9]([a-z0-9-]*[a-z0-9])?\.svc\.cluster\.local:[0-9]{1,5}$`
	// DefaultDeniedUpstream refuses platform internals by service name and port:
	// Kratos admin, OPA/OPAL, Redis, Postgres, the API server.
	DefaultDeniedUpstream = `^https?://(([a-z0-9-]+-)?(kratos-admin|opa|opal-client|opal-server|redis|redis-master|postgres|postgresql|kubernetes)\.|[^/]*:(4434|8181|7002|6379|5432)$)`
)

// Register binds the flags on fs; call Load after fs.Parse.
func Register(fs *flag.FlagSet) *Raw {
	r := &Raw{}
	s := func(p *string, name, def, usage string) {
		fs.StringVar(p, name, env(name, def), usage)
	}
	s(&r.GatewayNamespace, "gateway-namespace", "auth", "namespace of Sites, Rules, Ingresses and the gateway")
	s(&r.GatewayService, "gateway-service", "auth-oathkeeper-proxy", "oathkeeper proxy Service every Ingress points at")
	s(&r.GatewayServicePort, "gateway-service-port", "http", "port name of the oathkeeper proxy Service")
	s(&r.ReservedHosts, "reserved-hosts", "", "comma-separated hosts only system sites may use")
	s(&r.IngressClasses, "ingress-classes", "nginx", "comma-separated allowed ingress classes, first is default")
	s(&r.IngressAnnotations, "ingress-annotations", "", "comma-separated key=value annotations stamped on every Ingress")
	s(&r.Issuers, "issuers", "letsencrypt-prod", "comma-separated allowed ClusterIssuers, first is default")
	s(&r.AllowedUpstream, "allowed-upstream", DefaultAllowedUpstream, "regex every rendered upstream URL must match")
	s(&r.DeniedUpstream, "denied-upstream", DefaultDeniedUpstream, "regex no rendered upstream URL may match")
	s(&r.EnabledAuthenticators, "enabled-authenticators", "noop,cookie_session,bearer_token,oauth2_introspection", "globally enabled authenticators")
	s(&r.EnabledAuthorizers, "enabled-authorizers", "allow,deny,remote_json", "globally enabled authorizers")
	s(&r.EnabledMutators, "enabled-mutators", "noop,header,hydrator", "globally enabled mutators")
	s(&r.EnabledErrors, "enabled-errors", "json,redirect", "globally enabled error handlers")
	s(&r.RulesConfigMap, "rules-configmap", "", "maester configMapName written into every Rule (empty: sidecar mode)")
	s(&r.ZonesConfigMap, "zones-configmap", "site-operator-zones", "ConfigMap the Zone domains are mirrored into for admission")
	s(&r.PausedRedirectURL, "paused-redirect-url", "", "page browsers see for a paused site (empty: json error only)")
	s(&r.GatekitURL, "gatekit-url", "http://gatekit:8080", "gatekit base URL")
	fs.BoolVar(&r.EnableCertificates, "enable-certificates", env("enable-certificates", "true") == "true", "manage cert-manager Certificates")
	return r
}

// Raw is the unparsed flag set.
type Raw struct {
	GatewayNamespace, GatewayService, GatewayServicePort          string
	ReservedHosts, IngressClasses, IngressAnnotations, Issuers    string
	AllowedUpstream, DeniedUpstream                               string
	EnabledAuthenticators, EnabledAuthorizers                     string
	EnabledMutators, EnabledErrors                                string
	RulesConfigMap, ZonesConfigMap, GatekitURL, PausedRedirectURL string
	EnableCertificates                                            bool
}

// Load validates and converts the raw flags.
func (r *Raw) Load() (*Config, error) {
	c := &Config{
		GatewayNamespace:      r.GatewayNamespace,
		GatewayService:        r.GatewayService,
		GatewayServicePort:    r.GatewayServicePort,
		ReservedHosts:         list(r.ReservedHosts),
		IngressClasses:        list(r.IngressClasses),
		IngressAnnotations:    map[string]string{},
		Issuers:               list(r.Issuers),
		EnabledAuthenticators: list(r.EnabledAuthenticators),
		EnabledAuthorizers:    list(r.EnabledAuthorizers),
		EnabledMutators:       list(r.EnabledMutators),
		EnabledErrors:         list(r.EnabledErrors),
		RulesConfigMap:        r.RulesConfigMap,
		ZonesConfigMap:        r.ZonesConfigMap,
		GatekitURL:            strings.TrimRight(r.GatekitURL, "/"),
		PausedRedirectURL:     r.PausedRedirectURL,
		EnableCertificates:    r.EnableCertificates,
	}
	for _, kv := range list(r.IngressAnnotations) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("ingress-annotations: %q is not key=value", kv)
		}
		c.IngressAnnotations[k] = v
	}
	if len(c.IngressClasses) == 0 || len(c.Issuers) == 0 {
		return nil, fmt.Errorf("ingress-classes and issuers must not be empty")
	}
	var err error
	if c.AllowedUpstream, err = regexp.Compile(r.AllowedUpstream); err != nil {
		return nil, fmt.Errorf("allowed-upstream: %w", err)
	}
	if c.DeniedUpstream, err = regexp.Compile(r.DeniedUpstream); err != nil {
		return nil, fmt.Errorf("denied-upstream: %w", err)
	}
	return c, nil
}

// Default returns the configuration built from the flag defaults (used by tests).
func Default() *Config {
	fs := flag.NewFlagSet("default", flag.ContinueOnError)
	c, err := Register(fs).Load()
	if err != nil {
		panic(err)
	}
	return c
}

func env(flagName, def string) string {
	if v, ok := os.LookupEnv("SITE_OPERATOR_" + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))); ok {
		return v
	}
	return def
}

func list(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
