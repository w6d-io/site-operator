package controller

import (
	"context"
	"slices"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/render"
)

// siteOwner is a plain (non-controller) owner reference to site: a per-host
// Ingress has one per Site on its host and goes away with the last one.
func siteOwner(site *authv1.Site) metav1.OwnerReference {
	return metav1.OwnerReference{APIVersion: authv1.GroupVersion.String(), Kind: "Site", Name: site.Name, UID: site.UID}
}

func ownedBySite(ing *networkingv1.Ingress, name string) bool {
	return slices.ContainsFunc(ing.OwnerReferences, func(o metav1.OwnerReference) bool { return o.Kind == "Site" && o.Name == name })
}

func hostIngress(ing *networkingv1.Ingress) bool {
	return ing.Labels[render.ManagedByLabel] == render.ManagedBy && ing.Labels[render.HostIngressLabel] == "true"
}

// hostIngresses gives each host of site under a per-site Zone its shared
// Ingress, with site among its owners. A host another Ingress serves exactly
// gets none (an existing one is kept, not taken down). Host Ingresses site no
// longer needs are released.
func (r *SiteReconciler) hostIngresses(ctx context.Context, site *authv1.Site, hosts []string, zones map[string]*authv1.Zone, obs *observed) error {
	var keep []string
	for _, h := range hosts {
		taken, shadowed, err := r.hostCheck(ctx, site, []string{h})
		if err != nil {
			return err
		}
		obs.shadowed = appendNew(obs.shadowed, shadowed...)
		if taken != "" && obs.hostTaken == "" {
			obs.hostTaken = taken
		}
		want := render.HostIngress(h, zones[h], r.Config)
		keep = append(keep, want.Name)
		got := &networkingv1.Ingress{}
		err = r.Get(ctx, client.ObjectKeyFromObject(want), got)
		switch {
		case apierrors.IsNotFound(err):
			if taken != "" {
				continue // nothing created
			}
			want.OwnerReferences = []metav1.OwnerReference{siteOwner(site)}
			if err := r.Create(ctx, want); err != nil {
				return err
			}
			r.Recorder.Eventf(site, "Normal", "IngressCreated", "created Ingress %s for %s", want.Name, h)
			obs.hostIngresses = append(obs.hostIngresses, want)
			continue
		case err != nil:
			return err
		case !hostIngress(got):
			obs.conflict = "Ingress " + want.Name
			continue
		}
		changed := false
		if !ownedBySite(got, site.Name) {
			got.OwnerReferences = append(got.OwnerReferences, siteOwner(site))
			changed = true
		}
		if taken == "" && (got.Annotations[render.SpecHashAnnotation] != want.Annotations[render.SpecHashAnnotation] ||
			!maps(got.Labels, want.Labels) || !maps(got.Annotations, want.Annotations)) {
			got.Spec, got.Labels, got.Annotations = want.Spec, want.Labels, want.Annotations
			changed = true
		}
		if changed {
			if err := r.Update(ctx, got); err != nil {
				return err
			}
		}
		obs.hostIngresses = append(obs.hostIngresses, got)
	}
	return r.releaseHosts(ctx, site.Namespace, site.Name, keep)
}

// releaseHosts removes Site name from the owners of the host Ingresses not in
// keep, and deletes those left without any Site owner. It also runs when a Site
// is gone, so a host Ingress never outlives its last Site even without the GC.
func (r *SiteReconciler) releaseHosts(ctx context.Context, ns, name string, keep []string) error {
	var list networkingv1.IngressList
	if err := r.List(ctx, &list, client.InNamespace(ns), client.MatchingLabels{render.HostIngressLabel: "true", render.ManagedByLabel: render.ManagedBy}); err != nil {
		return err
	}
	for i := range list.Items {
		ing := &list.Items[i]
		if slices.Contains(keep, ing.Name) || !ownedBySite(ing, name) {
			continue
		}
		ing.OwnerReferences = slices.DeleteFunc(ing.OwnerReferences, func(o metav1.OwnerReference) bool { return o.Kind == "Site" && o.Name == name })
		var err error
		if !slices.ContainsFunc(ing.OwnerReferences, func(o metav1.OwnerReference) bool { return o.Kind == "Site" }) {
			err = client.IgnoreNotFound(r.Delete(ctx, ing))
		} else {
			err = r.Update(ctx, ing)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
