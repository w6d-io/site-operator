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

// ZoneSiteIngress is a Site's exact-host Ingress for its hosts under per-site
// Zones (hosts: host → its Zone, in Site order): the fixed template, backend the
// gateway, TLS from each Zone's settings (none for mode default). nil when the
// Site has no such host.
func ZoneSiteIngress(site *authv1.Site, hosts []string, zones map[string]*authv1.Zone, cfg *config.Config) *networkingv1.Ingress {
	if len(hosts) == 0 {
		return nil
	}
	var tls []networkingv1.IngressTLS
	bySecret := map[string]int{}
	for _, h := range hosts {
		s := ZoneSecret(zones[h])
		if s == "" {
			continue
		}
		if i, ok := bySecret[s]; ok {
			tls[i].Hosts = append(tls[i].Hosts, h)
			continue
		}
		bySecret[s] = len(tls)
		tls = append(tls, networkingv1.IngressTLS{Hosts: []string{h}, SecretName: s})
	}
	spec := ingressSpec(ZoneIngressClass(zones[hosts[0]], cfg), hosts, tls, cfg)
	return ingress(meta(site, IngressName(site), ingressHash(spec, cfg)), spec, cfg)
}
