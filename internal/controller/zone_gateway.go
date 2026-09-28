package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/render"
)

// checkGateway refuses a Zone gateway the operator may not use.
func (r *ZoneReconciler) checkGateway(zone *authv1.Zone) (string, string) {
	gw := zone.Spec.Gateway
	if gw == nil {
		return "", ""
	}
	if !r.Config.EnableGatewayAPI {
		return "GatewayAPIDisabled", "the Gateway API is disabled on this operator (--enable-gateway-api)"
	}
	if !slices.Contains(r.Config.Gateways, gw.Key()) {
		return "GatewayNotAllowed", "gateway " + gw.Key() + " is not allowed (allowed: " + fmt.Sprint(r.Config.Gateways) + ")"
	}
	if zone.Spec.OwnListener() && zone.Spec.TLS.Mode == authv1.ZoneTLSIssuer && !r.Config.EnableCertificates {
		return "CertificatesDisabled", "certificates are disabled on this operator"
	}
	return "", ""
}

// gateway writes (or removes) the Zone's ListenerSet and reports GatewayReady:
// the Gateway exists and is programmed, and a listener covers *.<domain> —
// the Gateway's own (tls default) or the Zone's ListenerSet (tls issuer/secret).
func (r *ZoneReconciler) gateway(ctx context.Context, kids children, zone *authv1.Zone) error {
	key := client.ObjectKey{Namespace: r.Config.GatewayNamespace, Name: render.ZoneName(zone)}
	if !zone.Spec.OwnListener() && r.Config.EnableGatewayAPI {
		if err := kids.deleteKind(ctx, zone, render.ListenerSetGVK, key); err != nil {
			return err
		}
	}
	if !zone.Spec.Routed() {
		setZoneCondition(zone, authv1.ConditionGatewayReady, metav1.ConditionTrue, "NoGateway", "the zone is not attached to a Gateway")
		return nil
	}
	ref := zone.Spec.Gateway
	gw := &unstructured.Unstructured{}
	gw.SetGroupVersionKind(render.GatewayGVK)
	if err := r.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, gw); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return err
		}
		setZoneCondition(zone, authv1.ConditionGatewayReady, metav1.ConditionFalse, "GatewayNotFound", "gateway "+ref.Key()+" does not exist")
		return nil
	}
	if ok, reason, msg := gatewayProgrammed(gw); !ok {
		setZoneCondition(zone, authv1.ConditionGatewayReady, metav1.ConditionFalse, reason, "gateway "+ref.Key()+": "+msg)
		return nil
	}
	at := gatewayAddress(gw)
	if !zone.Spec.OwnListener() {
		listener, reason, msg := coveringListener(gw, zone)
		if listener == "" {
			setZoneCondition(zone, authv1.ConditionGatewayReady, metav1.ConditionFalse, reason, msg)
			return nil
		}
		setZoneCondition(zone, authv1.ConditionGatewayReady, metav1.ConditionTrue, "Programmed",
			fmt.Sprintf("gateway %s at %s, listener %s (*.%s)", ref.Key(), at, listener, zone.Spec.Domain))
		return nil
	}
	ls, err := kids.object(ctx, zone, render.ZoneListenerSet(zone, r.Config))
	if errors.Is(err, errConflict) {
		setZoneCondition(zone, authv1.ConditionGatewayReady, metav1.ConditionFalse, "NameConflict", "ListenerSet "+key.Name+" "+errConflict.Error())
		return nil
	}
	if err != nil {
		return err
	}
	if ok, reason, msg := listenerSetReady(ls); !ok {
		setZoneCondition(zone, authv1.ConditionGatewayReady, metav1.ConditionFalse, reason, "ListenerSet "+key.Name+": "+msg)
		return nil
	}
	setZoneCondition(zone, authv1.ConditionGatewayReady, metav1.ConditionTrue, "Programmed",
		fmt.Sprintf("gateway %s at %s, ListenerSet %s (*.%s)", ref.Key(), at, key.Name, zone.Spec.Domain))
	return nil
}

func gatewayProgrammed(gw *unstructured.Unstructured) (bool, string, string) {
	conds, _, _ := unstructured.NestedSlice(gw.Object, "status", "conditions")
	ok, reason, msg, found := findCondition(conds, "Programmed")
	if !found {
		return false, "GatewayPending", "the gateway controller has not programmed it yet"
	}
	if !ok {
		return false, "GatewayNotProgrammed", msg
	}
	return true, reason, msg
}

// gatewayAddress is the first status address of a Gateway ("pending" if none).
func gatewayAddress(gw *unstructured.Unstructured) string {
	addrs, _, _ := unstructured.NestedSlice(gw.Object, "status", "addresses")
	for _, a := range addrs {
		if m, ok := a.(map[string]any); ok {
			if v, _ := m["value"].(string); v != "" {
				return v
			}
		}
	}
	return "pending"
}

// coveringListener is the Gateway's HTTPS listener serving *.<domain> with its
// own certificate: hostname exactly *.<domain> (a TLS wildcard covers one label,
// so a listener one level up would serve these hosts a certificate that does not
// match), programmed, and the one named by sectionName when set.
func coveringListener(gw *unstructured.Unstructured, zone *authv1.Zone) (name, reason, msg string) {
	want := "*." + zone.Spec.Domain
	section := zone.Spec.Gateway.SectionName
	listeners, _, _ := unstructured.NestedSlice(gw.Object, "spec", "listeners")
	for _, l := range listeners {
		m, _ := l.(map[string]any)
		n, _ := m["name"].(string)
		host, _ := m["hostname"].(string)
		proto, _ := m["protocol"].(string)
		if (section != "" && n != section) || proto != "HTTPS" || host != want {
			continue
		}
		if ok, lr, lm := listenerProgrammed(gw, n); !ok {
			return "", lr, "listener " + n + ": " + lm
		}
		return n, "", ""
	}
	where := "no HTTPS listener"
	if section != "" {
		where = "listener " + section + " is not an HTTPS listener"
	}
	return "", "ListenerDoesNotCover", fmt.Sprintf("gateway %s: %s for %s; use tls issuer or secret for a zone listener", zone.Spec.Gateway.Key(), where, want)
}

func listenerProgrammed(gw *unstructured.Unstructured, name string) (bool, string, string) {
	sts, _, _ := unstructured.NestedSlice(gw.Object, "status", "listeners")
	for _, s := range sts {
		m, _ := s.(map[string]any)
		if m["name"] != name {
			continue
		}
		conds, _, _ := unstructured.NestedSlice(m, "conditions")
		if ok, reason, msg, found := findCondition(conds, "Programmed"); found {
			return ok, reason, msg
		}
	}
	return false, "ListenerPending", "not programmed yet"
}

// listenerSetReady: the ListenerSet is accepted by its Gateway (the gateway
// namespace must be allowed by allowedListeners) and its listener programmed.
func listenerSetReady(ls *unstructured.Unstructured) (bool, string, string) {
	conds, _, _ := unstructured.NestedSlice(ls.Object, "status", "conditions")
	for _, typ := range []string{"Accepted", "Programmed"} {
		ok, reason, msg, found := findCondition(conds, typ)
		if !found {
			return false, "ListenerSetPending", "the gateway controller has not reported yet"
		}
		if !ok {
			return false, reason, msg
		}
	}
	return true, "", ""
}

// zonesForGateway re-reconciles the Zones attached to a Gateway.
func (r *ZoneReconciler) zonesForGateway(ctx context.Context, o client.Object) []reconcile.Request {
	var zones authv1.ZoneList
	if err := r.List(ctx, &zones); err != nil {
		return nil
	}
	var out []reconcile.Request
	for _, z := range zones.Items {
		if g := z.Spec.Gateway; g != nil && g.Namespace == o.GetNamespace() && g.Name == o.GetName() {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKey{Name: z.Name}})
		}
	}
	return out
}
