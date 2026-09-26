package controller

import (
	"context"
	"fmt"
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

// servesExactly reports whether an Ingress rule host is host itself.
func servesExactly(rule, host string) bool { return rule == host }

// servesByWildcard reports whether an Ingress rule host is a wildcard one label
// above host (which an exact-host Ingress for host overrides in nginx).
func servesByWildcard(rule, host string) bool {
	suffix, ok := strings.CutPrefix(rule, "*")
	return ok && strings.HasPrefix(suffix, ".") && strings.HasSuffix(host, suffix) &&
		!strings.Contains(strings.TrimSuffix(host, suffix), ".")
}

// serves reports whether an Ingress rule host serves host, exactly or by wildcard.
func serves(rule, host string) bool { return servesExactly(rule, host) || servesByWildcard(rule, host) }

// hostCheck looks at every Ingress in the cluster not controlled by site. An
// exact-host one takes the host ("<ns>/<name> serves <host>", blocking); a
// wildcard one is only shadowed for that host by the Site's exact-host Ingress
// (nginx: exact server block wins), reported as a warning. This operator's own
// Zone wildcards are expected and skipped.
func (r *SiteReconciler) hostCheck(ctx context.Context, site *authv1.Site, hosts []string) (taken string, shadowed []string, err error) {
	if len(hosts) == 0 {
		return "", nil, nil
	}
	var list networkingv1.IngressList
	if err := r.List(ctx, &list); err != nil { // the Ingress cache is cluster-wide
		return "", nil, err
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
				switch {
				case servesExactly(rule.Host, h) && taken == "":
					taken = ing.Namespace + "/" + ing.Name + " serves " + h
				case servesByWildcard(rule.Host, h):
					var paths []string
					if rule.HTTP != nil {
						for _, p := range rule.HTTP.Paths {
							paths = append(paths, p.Path)
						}
					}
					msg := fmt.Sprintf("%s/%s serves %s; nginx routes %s to this Site (paths of that Ingress, e.g. %s, are not served on this host)",
						ing.Namespace, ing.Name, rule.Host, h, strings.Join(paths, ", "))
					if !slices.Contains(shadowed, msg) {
						shadowed = append(shadowed, msg)
					}
				}
			}
		}
	}
	return taken, shadowed, nil
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
