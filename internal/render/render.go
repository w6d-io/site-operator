// Package render turns a Site into its child objects. Every function is pure:
// the same Site and config always yield the same objects and names.
package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
)

const (
	SiteLabel          = "auth.w6d.io/site"
	GateLabel          = "auth.w6d.io/gate"
	ZoneLabel          = "auth.w6d.io/zone"
	ManagedByLabel     = "app.kubernetes.io/managed-by"
	ManagedBy          = "site-operator"
	SpecHashAnnotation = "auth.w6d.io/spec-hash"
	RetiredAnnotation  = "auth.w6d.io/retired"
)

// CertificateGVK is the cert-manager Certificate kind (handled unstructured, no dependency).
var CertificateGVK = schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"}

// Hash is the first 8 hex chars of the sha256 of v's JSON encoding.
func Hash(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // only plain structs are hashed
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:4])
}

// IngressName is the name of the Site's Ingress and Certificate.
func IngressName(site *authv1.Site) string { return "site-" + site.Name }

func meta(site *authv1.Site, name, hash string) metav1.ObjectMeta {
	return owned("Site", site.Name, site.UID, site.Namespace, name, hash, map[string]string{SiteLabel: site.Name})
}

func owned(kind, owner string, uid types.UID, ns, name, hash string, labels map[string]string) metav1.ObjectMeta {
	t := true
	labels[ManagedByLabel] = ManagedBy
	return metav1.ObjectMeta{
		Name:        name,
		Namespace:   ns,
		Labels:      labels,
		Annotations: map[string]string{SpecHashAnnotation: hash},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: authv1.GroupVersion.String(), Kind: kind,
			Name: owner, UID: uid, Controller: &t, BlockOwnerDeletion: &t,
		}},
	}
}

// templated is what Oathkeeper compiles and caches under the rule id
// (remote/remote_json payload, header/cookie/id_token templates).
type templated struct {
	Authorizer *okv1.Handler   `json:"authorizer"`
	Mutators   []*okv1.Handler `json:"mutators"`
}

// UpstreamURL renders the in-cluster URL of a structured upstream.
func UpstreamURL(u authv1.Upstream) string {
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s.%s.svc.cluster.local:%d", scheme, u.Service, u.Namespace, u.Port)
}

// Upstreams returns the upstream of every gate (the Site's unless overridden).
func Upstreams(site *authv1.Site) []authv1.Upstream {
	out := make([]authv1.Upstream, 0, len(site.Spec.Gates))
	for _, g := range site.Spec.Gates {
		if g.Upstream != nil {
			out = append(out, *g.Upstream)
		} else {
			out = append(out, site.Spec.Upstream)
		}
	}
	return out
}

// Rules renders one maester Rule per gate. The name ends with the hash of the
// parts Oathkeeper caches by rule id (authorizer and mutator configs hold the
// payload and header templates), so a template change yields a new Rule and a
// new rule id (swapped, see README "Rule swaps"), while any other change keeps
// the name and updates the Rule in place: one maester write, no gap.
func Rules(site *authv1.Site, cfg *config.Config) []*okv1.Rule {
	out := make([]*okv1.Rule, 0, len(site.Spec.Gates))
	ups := Upstreams(site)
	for i, g := range site.Spec.Gates {
		up := ups[i]
		spec := okv1.RuleSpec{
			Upstream:   &okv1.Upstream{URL: UpstreamURL(up), PreserveHost: &up.PreserveHost},
			Match:      &okv1.Match{URL: g.Match.URL, Methods: append([]string{}, g.Match.Methods...)},
			Authorizer: handler(g.Authorizer),
		}
		if up.StripPath != "" {
			sp := up.StripPath
			spec.Upstream.StripPath = &sp
		}
		spec.Authenticators = handlers(g.Authenticators)
		spec.Mutators = handlers(g.Mutators)
		spec.Errors = handlers(g.Errors)
		if cfg.RulesConfigMap != "" {
			cm := cfg.RulesConfigMap
			spec.ConfigMapName = &cm
		}
		m := meta(site, site.Name+"-"+g.Name+"-"+Hash(templated{spec.Authorizer, spec.Mutators}), Hash(spec))
		m.Labels[GateLabel] = g.Name
		out = append(out, &okv1.Rule{ObjectMeta: m, Spec: spec})
	}
	return out
}

// Retire neutralizes a Rule that is about to be deleted: its match URL is moved
// to a unique, unroutable host, so any copy of it that maester still writes
// (stale informer cache, finalizer pending) can never overlap its replacement.
func Retire(r *okv1.Rule) {
	r.Spec.Match = &okv1.Match{URL: "https://" + r.Name + ".retired.invalid/", Methods: r.Spec.Match.Methods}
	if r.Annotations == nil {
		r.Annotations = map[string]string{}
	}
	r.Annotations[RetiredAnnotation] = "true"
}

// Retired reports whether r was neutralized by Retire.
func Retired(r *okv1.Rule) bool { return r.Annotations[RetiredAnnotation] == "true" }

func handler(h authv1.Handler) *okv1.Handler {
	out := &okv1.Handler{Handler: h.Handler}
	if h.Config != nil && len(h.Config.Raw) > 0 {
		out.Config = &runtime.RawExtension{Raw: canonical(h.Config.Raw)}
	}
	return out
}

// canonical re-encodes JSON with sorted keys, as the API server stores it, so
// hashes and drift comparisons are stable across round-trips.
func canonical(raw []byte) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}

func handlers(in []authv1.Handler) []*okv1.Handler {
	if len(in) == 0 {
		return nil
	}
	out := make([]*okv1.Handler, 0, len(in))
	for _, h := range in {
		out = append(out, handler(h))
	}
	return out
}

// IngressClass is the Site's class or the operator default.
func IngressClass(site *authv1.Site, cfg *config.Config) string {
	if site.Spec.Exposure.IngressClass != "" {
		return site.Spec.Exposure.IngressClass
	}
	return cfg.IngressClasses[0]
}

// Issuer is the Site's issuer or the operator default.
func Issuer(site *authv1.Site, cfg *config.Config) string {
	if site.Spec.Exposure.Issuer != "" {
		return site.Spec.Exposure.Issuer
	}
	return cfg.Issuers[0]
}

// Ingress is the fixed template for a vanity Site Ingress: inputs are only the
// Site name, hosts, class and TLS mode. The backend is always the gateway
// Service; annotations come from the operator config only.
func Ingress(site *authv1.Site, cfg *config.Config) *networkingv1.Ingress {
	var tls []networkingv1.IngressTLS
	if site.Spec.Exposure.TLS == authv1.TLSPerSite {
		tls = []networkingv1.IngressTLS{{Hosts: append([]string{}, site.Spec.Hosts...), SecretName: IngressName(site) + "-tls"}}
	}
	spec := ingressSpec(IngressClass(site, cfg), site.Spec.Hosts, tls, cfg)
	return ingress(meta(site, IngressName(site), ingressHash(spec, cfg)), spec, cfg)
}

func ingressSpec(cls string, hosts []string, tls []networkingv1.IngressTLS, cfg *config.Config) networkingv1.IngressSpec {
	pt := networkingv1.PathTypeImplementationSpecific
	spec := networkingv1.IngressSpec{IngressClassName: &cls, TLS: tls}
	for _, h := range hosts {
		spec.Rules = append(spec.Rules, networkingv1.IngressRule{
			Host: h,
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{
					Path: "/", PathType: &pt,
					Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{
						Name: cfg.GatewayService, Port: networkingv1.ServiceBackendPort{Name: cfg.GatewayServicePort},
					}},
				}},
			}},
		})
	}
	return spec
}

func ingressHash(spec networkingv1.IngressSpec, cfg *config.Config) string {
	return Hash(struct {
		Spec networkingv1.IngressSpec
		Ann  map[string]string
	}{spec, cfg.IngressAnnotations})
}

func ingress(m metav1.ObjectMeta, spec networkingv1.IngressSpec, cfg *config.Config) *networkingv1.Ingress {
	ing := &networkingv1.Ingress{ObjectMeta: m, Spec: spec}
	for k, v := range cfg.IngressAnnotations {
		ing.Annotations[k] = v
	}
	return ing
}

// Certificate renders the per-site cert-manager Certificate. Its Secret is the
// Site's own (never a shared multi-SAN one), so owner-based GC is safe.
func Certificate(site *authv1.Site, cfg *config.Config) *unstructured.Unstructured {
	return certificate(func(h string) metav1.ObjectMeta { return meta(site, IngressName(site), h) },
		site.Spec.Hosts, IngressName(site)+"-tls", Issuer(site, cfg))
}

func certificate(m func(hash string) metav1.ObjectMeta, hosts []string, secret, issuer string) *unstructured.Unstructured {
	dns := make([]any, 0, len(hosts))
	for _, h := range hosts {
		dns = append(dns, h)
	}
	spec := map[string]any{
		"secretName": secret,
		"dnsNames":   dns,
		"issuerRef":  map[string]any{"name": issuer, "kind": "ClusterIssuer", "group": "cert-manager.io"},
	}
	om := m(Hash(spec))
	u := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	u.SetGroupVersionKind(CertificateGVK)
	u.SetName(om.Name)
	u.SetNamespace(om.Namespace)
	u.SetLabels(om.Labels)
	u.SetAnnotations(om.Annotations)
	u.SetOwnerReferences(om.OwnerReferences)
	return u
}
