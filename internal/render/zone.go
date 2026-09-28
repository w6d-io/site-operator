package render

import (
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
)

// ZoneName is the name of the Zone's Ingress and Certificate (gateway namespace).
func ZoneName(z *authv1.Zone) string { return "zone-" + z.Name }

// ZoneSecret is the TLS Secret the Zone's Ingress uses ("" for the controller default).
func ZoneSecret(z *authv1.Zone) string {
	switch z.Spec.TLS.Mode {
	case authv1.ZoneTLSSecret:
		return z.Spec.TLS.SecretName
	case authv1.ZoneTLSIssuer:
		return ZoneName(z) + "-tls"
	}
	return ""
}

// ZoneIngressClass is the Zone's class or the operator default.
func ZoneIngressClass(z *authv1.Zone, cfg *config.Config) string {
	if z.Spec.IngressClass != "" {
		return z.Spec.IngressClass
	}
	return cfg.IngressClasses[0]
}

// ZoneIssuer is the Zone's issuer or the operator default.
func ZoneIssuer(z *authv1.Zone, cfg *config.Config) string {
	if z.Spec.TLS.Issuer != "" {
		return z.Spec.TLS.Issuer
	}
	return cfg.Issuers[0]
}

func zoneMeta(z *authv1.Zone, cfg *config.Config, hash string) metav1.ObjectMeta {
	return owned("Zone", z.Name, z.UID, cfg.GatewayNamespace, ZoneName(z), hash, map[string]string{ZoneLabel: z.Name})
}

// ZoneIngress is the one wildcard Ingress of a Zone: host *.<domain>, backend the
// gateway. Every Site host under the Zone is served by it.
func ZoneIngress(z *authv1.Zone, cfg *config.Config) *networkingv1.Ingress {
	host := "*." + z.Spec.Domain
	var tls []networkingv1.IngressTLS
	if s := ZoneSecret(z); s != "" {
		tls = []networkingv1.IngressTLS{{Hosts: []string{host}, SecretName: s}}
	}
	spec := ingressSpec(ZoneIngressClass(z, cfg), []string{host}, tls, cfg)
	return ingress(zoneMeta(z, cfg, ingressHash(spec, cfg)), spec, cfg)
}

// ZoneCertificate is the wildcard Certificate for mode issuer (needs a DNS-01 issuer).
func ZoneCertificate(z *authv1.Zone, cfg *config.Config) *unstructured.Unstructured {
	return certificate(func(h string) metav1.ObjectMeta { return zoneMeta(z, cfg, h) },
		[]string{"*." + z.Spec.Domain}, ZoneSecret(z), ZoneIssuer(z, cfg))
}

// HostIngressLabel marks the shared per-host Ingresses of per-site Zones.
const (
	HostIngressLabel = "auth.w6d.io/host-ingress"
	// HostAnnotation carries the host a per-host Ingress serves (labels are too short for hosts).
	HostAnnotation = "auth.w6d.io/host"
)

// HostIngressName names the Ingress of one host under a per-site Zone.
func HostIngressName(host string) string { return "host-" + Hash(host) }

// HostIngress is the exact-host Ingress of one host under a per-site Zone,
// shared by every Site on that host (each one an owner, none the controller,
// so it goes away with the last one): the fixed template, backend the gateway,
// TLS from the Zone (none for mode default). Owner references are set by the caller.
func HostIngress(host string, zone *authv1.Zone, cfg *config.Config) *networkingv1.Ingress {
	var tls []networkingv1.IngressTLS
	if s := ZoneSecret(zone); s != "" {
		tls = []networkingv1.IngressTLS{{Hosts: []string{host}, SecretName: s}}
	}
	spec := ingressSpec(ZoneIngressClass(zone, cfg), []string{host}, tls, cfg)
	m := metav1.ObjectMeta{
		Name: HostIngressName(host), Namespace: cfg.GatewayNamespace,
		Labels:      map[string]string{ManagedByLabel: ManagedBy, HostIngressLabel: "true", ZoneLabel: zone.Name},
		Annotations: map[string]string{SpecHashAnnotation: ingressHash(spec, cfg), HostAnnotation: host},
	}
	return ingress(m, spec, cfg)
}
