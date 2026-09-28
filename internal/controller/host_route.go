package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
	"github.com/w6d-io/site-operator/internal/render"
	"github.com/w6d-io/site-operator/internal/validate"
)

// routeHosts are the Site's hosts under a Zone with a gateway (in Site order).
// A Zone whose gateway the operator may not use (the Zone reports why) gives
// its hosts no route; refused says so for RouteReady.
func routeHosts(site *authv1.Site, zones []authv1.Zone, cfg *config.Config) (hosts []string, byHost map[string]*authv1.Zone, refused string) {
	byHost = map[string]*authv1.Zone{}
	for _, h := range site.Spec.Hosts {
		z := validate.HostZone(h, zones)
		if z == nil || !z.Spec.Routed() {
			continue
		}
		switch {
		case !cfg.EnableGatewayAPI:
			refused = "zone " + z.Name + ": the Gateway API is disabled on this operator"
		case !slices.Contains(cfg.Gateways, z.Spec.Gateway.Key()):
			refused = "zone " + z.Name + ": gateway " + z.Spec.Gateway.Key() + " is not allowed"
		default:
			hosts = append(hosts, h)
			byHost[h] = z
		}
	}
	return hosts, byHost, refused
}

func newRoute() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(render.HTTPRouteGVK)
	return u
}

func ownedByName(refs []metav1.OwnerReference, name string) bool {
	return slices.ContainsFunc(refs, func(o metav1.OwnerReference) bool { return o.Kind == "Site" && o.Name == name })
}

// hostRouteOf reports whether an HTTPRoute is one of the operator's shared per-host routes.
func (r *SiteReconciler) hostRouteOf(u *unstructured.Unstructured) bool {
	l := u.GetLabels()
	return u.GetNamespace() == r.Config.GatewayNamespace && l[render.ManagedByLabel] == render.ManagedBy &&
		l[render.HostRouteLabel] == "true" && strings.HasPrefix(u.GetName(), "host-")
}

// hostRoutes gives each host of site under a Zone with a gateway its shared
// HTTPRoute, with site among its owners — the host Ingress lifecycle, on the
// Gateway. A host another route, listener or Ingress serves exactly gets none
// (an existing one is kept). Routes site no longer needs are released.
func (r *SiteReconciler) hostRoutes(ctx context.Context, site *authv1.Site, hosts []string, zones map[string]*authv1.Zone, obs *observed) error {
	var keep []string
	for _, h := range hosts {
		taken, shadowed, err := r.routeCheck(ctx, site, h, zones[h])
		if err != nil {
			return err
		}
		obs.shadowed = appendNew(obs.shadowed, shadowed...)
		if taken != "" && obs.routeTaken == "" {
			obs.routeTaken = taken
		}
		want := render.HostRoute(h, zones[h], r.Config)
		keep = append(keep, want.GetName())
		got := newRoute()
		err = r.Get(ctx, client.ObjectKeyFromObject(want), got)
		switch {
		case apierrors.IsNotFound(err):
			if taken != "" {
				continue // nothing created
			}
			want.SetOwnerReferences([]metav1.OwnerReference{siteOwner(site)})
			if err := r.Create(ctx, want); err != nil {
				return err
			}
			r.Recorder.Eventf(site, "Normal", "HTTPRouteCreated", "created HTTPRoute %s for %s", want.GetName(), h)
			obs.routes = append(obs.routes, want)
			continue
		case err != nil:
			return err
		case !r.hostRouteOf(got):
			obs.conflict = "HTTPRoute " + want.GetName()
			continue
		}
		changed := false
		if !ownedByName(got.GetOwnerReferences(), site.Name) {
			got.SetOwnerReferences(append(got.GetOwnerReferences(), siteOwner(site)))
			changed = true
		}
		if taken == "" && (!maps(got.GetLabels(), want.GetLabels()) || !maps(got.GetAnnotations(), want.GetAnnotations())) {
			got.Object["spec"] = want.Object["spec"]
			got.SetLabels(want.GetLabels())
			got.SetAnnotations(want.GetAnnotations())
			changed = true
		}
		if changed {
			if err := r.Update(ctx, got); err != nil {
				return err
			}
		}
		obs.routes = append(obs.routes, got)
	}
	if !r.Config.EnableGatewayAPI {
		return nil
	}
	return r.releaseRoutes(ctx, site.Namespace, site.Name, keep)
}

// releaseRoutes removes Site name from the owners of the host routes not in
// keep, and deletes those left without any Site owner (host Ingress rules).
func (r *SiteReconciler) releaseRoutes(ctx context.Context, ns, name string, keep []string) error {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(render.HTTPRouteGVK.GroupVersion().WithKind("HTTPRouteList"))
	if err := r.List(ctx, list, client.InNamespace(ns), client.MatchingLabels{render.HostRouteLabel: "true", render.ManagedByLabel: render.ManagedBy}); err != nil {
		return err
	}
	for i := range list.Items {
		rt := &list.Items[i]
		if slices.Contains(keep, rt.GetName()) || !ownedByName(rt.GetOwnerReferences(), name) {
			continue
		}
		refs := slices.DeleteFunc(rt.GetOwnerReferences(), func(o metav1.OwnerReference) bool { return o.Kind == "Site" && o.Name == name })
		var err error
		if !slices.ContainsFunc(refs, func(o metav1.OwnerReference) bool { return o.Kind == "Site" }) {
			err = client.IgnoreNotFound(r.Delete(ctx, rt))
		} else {
			rt.SetOwnerReferences(refs)
			err = r.Update(ctx, rt)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// routeHostnames reads spec.hostnames of an HTTPRoute.
func routeHostnames(u *unstructured.Unstructured) []string {
	hs, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "hostnames")
	return hs
}

// routeServesByWildcard: a Gateway API wildcard hostname (*.x) matches every
// host ending in .x, one label or more.
func routeServesByWildcard(rule, host string) bool {
	suffix, ok := strings.CutPrefix(rule, "*")
	return ok && strings.HasPrefix(suffix, ".") && strings.HasSuffix(host, suffix) && len(host) > len(suffix)
}

// routeCheck applies the host rules of an Ingress (hostCheck: a foreign
// Ingress naming the host takes it, since moving its DNS to the Gateway would
// hijack it) and, on the Gateway side: a foreign HTTPRoute naming the host
// takes it; a listener (the Gateway's or a ListenerSet on it) with that exact
// hostname takes it (it wins the match, so this route on the wildcard listener
// would never be reached); a foreign wildcard route is only shadowed (Envoy
// prefers the exact hostname), reported as a warning.
func (r *SiteReconciler) routeCheck(ctx context.Context, site *authv1.Site, host string, zone *authv1.Zone) (string, []string, error) {
	taken, shadowed, err := r.hostCheck(ctx, site, []string{host})
	if err != nil || !r.Config.EnableGatewayAPI {
		return taken, shadowed, err
	}
	routes := &unstructured.UnstructuredList{}
	routes.SetGroupVersionKind(render.HTTPRouteGVK.GroupVersion().WithKind("HTTPRouteList"))
	if err := r.List(ctx, routes); err != nil { // the HTTPRoute cache is cluster-wide
		return "", nil, err
	}
	slices.SortFunc(routes.Items, func(a, b unstructured.Unstructured) int {
		return strings.Compare(a.GetNamespace()+"/"+a.GetName(), b.GetNamespace()+"/"+b.GetName())
	})
	for i := range routes.Items {
		rt := &routes.Items[i]
		if r.hostRouteOf(rt) {
			continue
		}
		for _, h := range routeHostnames(rt) {
			switch {
			case h == host && taken == "":
				taken = fmt.Sprintf("HTTPRoute %s/%s serves %s", rt.GetNamespace(), rt.GetName(), host)
			case routeServesByWildcard(h, host):
				shadowed = appendNew(shadowed, fmt.Sprintf("HTTPRoute %s/%s serves %s; the gateway routes %s to this Site", rt.GetNamespace(), rt.GetName(), h, host))
			}
		}
	}
	if taken != "" {
		return taken, shadowed, nil
	}
	listener, err := r.exactListener(ctx, zone, host)
	if err != nil {
		return "", nil, err
	}
	if listener != "" {
		taken = listener + " serves " + host + " (exact hostname: it wins over the zone's listener)"
	}
	return taken, shadowed, nil
}

// exactListener names a listener on the zone's Gateway — its own or one of a
// ListenerSet attached to it — whose hostname is exactly host.
func (r *SiteReconciler) exactListener(ctx context.Context, zone *authv1.Zone, host string) (string, error) {
	ref := zone.Spec.Gateway
	gw := &unstructured.Unstructured{}
	gw.SetGroupVersionKind(render.GatewayGVK)
	if err := r.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, gw); client.IgnoreNotFound(err) != nil {
		return "", err
	}
	if n := listenerFor(gw, host); n != "" {
		return "listener " + n + " of Gateway " + ref.Key(), nil
	}
	sets := &unstructured.UnstructuredList{}
	sets.SetGroupVersionKind(render.ListenerSetGVK.GroupVersion().WithKind("ListenerSetList"))
	if err := r.List(ctx, sets); err != nil {
		return "", err
	}
	for i := range sets.Items {
		ls := &sets.Items[i]
		p, _, _ := unstructured.NestedStringMap(ls.Object, "spec", "parentRef")
		ns := p["namespace"]
		if ns == "" {
			ns = ls.GetNamespace()
		}
		if p["name"] != ref.Name || ns != ref.Namespace {
			continue
		}
		if n := listenerFor(ls, host); n != "" {
			return fmt.Sprintf("ListenerSet %s/%s (listener %s)", ls.GetNamespace(), ls.GetName(), n), nil
		}
	}
	return "", nil
}

// listenerFor names the listener of a Gateway or ListenerSet whose hostname is exactly host.
func listenerFor(u *unstructured.Unstructured, host string) string {
	ls, _, _ := unstructured.NestedSlice(u.Object, "spec", "listeners")
	for _, l := range ls {
		if m, ok := l.(map[string]any); ok && m["hostname"] == host {
			n, _ := m["name"].(string)
			return n
		}
	}
	return ""
}

// sitesForRoute re-reconciles the Sites whose hosts an HTTPRoute (anywhere)
// names or covers: one appearing makes them HostTaken, one going away frees them.
func (r *SiteReconciler) sitesForRoute(ctx context.Context, obj client.Object) []reconcile.Request {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return nil
	}
	return r.sitesOnHosts(ctx, routeHostnames(u))
}

// sitesForListenerSet re-reconciles the Sites whose hosts a ListenerSet lists.
func (r *SiteReconciler) sitesForListenerSet(ctx context.Context, obj client.Object) []reconcile.Request {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return nil
	}
	var hosts []string
	ls, _, _ := unstructured.NestedSlice(u.Object, "spec", "listeners")
	for _, l := range ls {
		if m, ok := l.(map[string]any); ok {
			if h, _ := m["hostname"].(string); h != "" {
				hosts = append(hosts, h)
			}
		}
	}
	return r.sitesOnHosts(ctx, hosts)
}

func (r *SiteReconciler) sitesOnHosts(ctx context.Context, rules []string) []reconcile.Request {
	var sites authv1.SiteList
	if err := r.List(ctx, &sites, client.InNamespace(r.Config.GatewayNamespace)); err != nil {
		return nil
	}
	var out []reconcile.Request
	for _, s := range sites.Items {
		if slices.ContainsFunc(s.Spec.Hosts, func(h string) bool {
			return slices.ContainsFunc(rules, func(rule string) bool { return rule == h || routeServesByWildcard(rule, h) })
		}) {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&s)})
		}
	}
	return out
}

func appendNew(list []string, items ...string) []string {
	for _, it := range items {
		if !slices.Contains(list, it) {
			list = append(list, it)
		}
	}
	return list
}
