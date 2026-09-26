package controller

import (
	"context"
	"slices"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/render"
	"github.com/w6d-io/site-operator/internal/validate"
)

// ingressHosts are the hosts a Site's own Ingress serves: every host for a
// vanity Site, else the hosts under per-site Zones (in Site order).
func ingressHosts(site *authv1.Site, zones []authv1.Zone) ([]string, map[string]*authv1.Zone) {
	byHost := map[string]*authv1.Zone{}
	var hosts []string
	for _, h := range site.Spec.Hosts {
		z := validate.HostZone(h, zones)
		if site.Spec.Exposure.Vanity() || (z != nil && z.Spec.PerSite()) {
			hosts = append(hosts, h)
			byHost[h] = z
		}
	}
	return hosts, byHost
}

// serves reports whether an Ingress rule host serves host: the same name, or a
// wildcard one label above it (which an exact-host Ingress would shadow).
func serves(rule, host string) bool {
	if rule == host {
		return true
	}
	suffix, ok := strings.CutPrefix(rule, "*")
	return ok && strings.HasPrefix(suffix, ".") && strings.HasSuffix(host, suffix) &&
		!strings.Contains(strings.TrimSuffix(host, suffix), ".")
}

// hostTaken names the first Ingress anywhere in the cluster, not controlled by
// site, that serves one of hosts ("<namespace>/<name> serves <host>"), or "".
// This operator's own Zone wildcard Ingresses are expected (a vanity Site under a
// wildcard Zone overrides it on purpose) and skipped.
func (r *SiteReconciler) hostTaken(ctx context.Context, site *authv1.Site, hosts []string) (string, error) {
	if len(hosts) == 0 {
		return "", nil
	}
	var list networkingv1.IngressList
	if err := r.List(ctx, &list); err != nil { // the Ingress cache is cluster-wide
		return "", err
	}
	slices.SortFunc(list.Items, func(a, b networkingv1.Ingress) int {
		return strings.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})
	for i := range list.Items {
		ing := &list.Items[i]
		if metav1.IsControlledBy(ing, site) || r.zoneWildcard(ing) {
			continue
		}
		for _, rule := range ing.Spec.Rules {
			for _, h := range hosts {
				if serves(rule.Host, h) {
					return ing.Namespace + "/" + ing.Name + " serves " + h, nil
				}
			}
		}
	}
	return "", nil
}

func (r *SiteReconciler) zoneWildcard(ing *networkingv1.Ingress) bool {
	return ing.Namespace == r.Config.GatewayNamespace && ing.Labels[render.ManagedByLabel] == render.ManagedBy &&
		ing.Labels[render.ZoneLabel] != "" && strings.HasPrefix(ing.Name, "zone-")
}

// sitesForIngress re-reconciles the Sites whose hosts an Ingress (anywhere)
// serves: one appearing makes them HostTaken, one going away frees them.
func (r *SiteReconciler) sitesForIngress(ctx context.Context, obj client.Object) []reconcile.Request {
	ing, ok := obj.(*networkingv1.Ingress)
	if !ok {
		return nil
	}
	var sites authv1.SiteList
	if err := r.List(ctx, &sites, client.InNamespace(r.Config.GatewayNamespace)); err != nil {
		return nil
	}
	var out []reconcile.Request
	for _, s := range sites.Items {
		if slices.ContainsFunc(s.Spec.Hosts, func(h string) bool {
			return slices.ContainsFunc(ing.Spec.Rules, func(rule networkingv1.IngressRule) bool { return serves(rule.Host, h) })
		}) {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&s)})
		}
	}
	return out
}
