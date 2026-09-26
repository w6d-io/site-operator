package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/render"
	"github.com/w6d-io/site-operator/internal/validate"
)

// readyInputs are the conditions Ready is the conjunction of.
var readyInputs = []string{
	authv1.ConditionValidated,
	authv1.ConditionRulesSynced,
	authv1.ConditionRulesLoaded,
	authv1.ConditionIngressReady,
	authv1.ConditionCertificateReady,
}

func setCondition(site *authv1.Site, typ string, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&site.Status.Conditions, metav1.Condition{
		Type: typ, Status: status, Reason: reason, Message: msg, ObservedGeneration: site.Generation,
	})
}

// setReady derives Ready from the other conditions: the first one that is not
// True (in readyInputs order) gives Ready its reason.
func setReady(site *authv1.Site) {
	for _, t := range readyInputs {
		c := meta.FindStatusCondition(site.Status.Conditions, t)
		if c == nil || c.ObservedGeneration != site.Generation {
			setCondition(site, authv1.ConditionReady, metav1.ConditionFalse, t+"Pending", t+" not evaluated for this generation")
			return
		}
		if c.Status != metav1.ConditionTrue {
			setCondition(site, authv1.ConditionReady, metav1.ConditionFalse, c.Reason, t+": "+c.Message)
			return
		}
	}
	setCondition(site, authv1.ConditionReady, metav1.ConditionTrue, "Ready", "all children are in place")
}

func setChildConditions(site *authv1.Site, desired []*okv1.Rule, obs *observed) {
	if obs.conflict != "" {
		setCondition(site, authv1.ConditionRulesSynced, metav1.ConditionFalse, "NameConflict", obs.conflict+" "+errConflict.Error())
	} else {
		setRulesSynced(site, desired, obs.rules)
	}
	setIngressReady(site, obs)
	setCertificateReady(site, obs)
}

// setRulesSynced is True once maester acknowledged every rendered Rule
// (status.validation.valid), i.e. it wrote them to the gateway rules.
func setRulesSynced(site *authv1.Site, desired, got []*okv1.Rule) {
	acked := 0
	for _, r := range got {
		v := r.Status.Validation
		if v == nil || v.Valid == nil {
			continue
		}
		if !*v.Valid {
			msg := ""
			if v.ValidationError != nil {
				msg = *v.ValidationError
			}
			setCondition(site, authv1.ConditionRulesSynced, metav1.ConditionFalse, "RuleRejected",
				fmt.Sprintf("maester rejected Rule %s: %s", r.Name, msg))
			return
		}
		acked++
	}
	if acked < len(desired) {
		setCondition(site, authv1.ConditionRulesSynced, metav1.ConditionFalse, "WaitingForMaester",
			fmt.Sprintf("%d/%d rules acknowledged by maester", acked, len(desired)))
		return
	}
	setCondition(site, authv1.ConditionRulesSynced, metav1.ConditionTrue, "Synced",
		fmt.Sprintf("%d rules written to the gateway rules", len(desired)))
}

func setIngressReady(site *authv1.Site, obs *observed) {
	switch {
	case obs.hostTaken != "":
		setCondition(site, authv1.ConditionIngressReady, metav1.ConditionFalse, "HostTaken",
			"another Ingress already serves this host: "+obs.hostTaken+"; nothing was created")
	case !obs.ownIngress:
		st, reason, msg := zoneCondition(site, obs.zones, authv1.ConditionIngressReady)
		setCondition(site, authv1.ConditionIngressReady, st, reason, msg)
	case obs.ingress == nil:
		setCondition(site, authv1.ConditionIngressReady, metav1.ConditionFalse, "NameConflict", obs.conflict+" "+errConflict.Error())
	case lbAddress(obs.ingress) == "":
		setCondition(site, authv1.ConditionIngressReady, metav1.ConditionFalse, "WaitingForAddress", "the ingress controller has not admitted the Ingress yet")
	default:
		setCondition(site, authv1.ConditionIngressReady, metav1.ConditionTrue, "Admitted", "load balancer "+lbAddress(obs.ingress))
	}
}

func setCertificateReady(site *authv1.Site, obs *observed) {
	e := site.Spec.Exposure
	switch {
	case !e.Vanity():
		st, reason, msg := zoneCondition(site, obs.zones, authv1.ConditionCertificateReady)
		setCondition(site, authv1.ConditionCertificateReady, st, reason, msg)
	case e.TLS != authv1.TLSPerSite:
		setCondition(site, authv1.ConditionCertificateReady, metav1.ConditionTrue, "NotRequired", "the ingress controller default certificate serves this host")
	case obs.cert == nil:
		setCondition(site, authv1.ConditionCertificateReady, metav1.ConditionFalse, "NameConflict", "Certificate "+errConflict.Error())
	default:
		if ok, reason, msg := certReady(obs.cert); ok {
			setCondition(site, authv1.ConditionCertificateReady, metav1.ConditionTrue, "Issued", msg)
		} else {
			setCondition(site, authv1.ConditionCertificateReady, metav1.ConditionFalse, reason, msg)
		}
	}
}

// zoneCondition reports a Site condition from the Zones serving its hosts: the
// Zone's wildcard Ingress and certificate are what make a zone host reachable.
func zoneCondition(site *authv1.Site, zones []authv1.Zone, typ string) (metav1.ConditionStatus, string, string) {
	var names []string
	for _, h := range site.Spec.Hosts {
		z := validate.HostZone(h, zones)
		if z == nil {
			return metav1.ConditionFalse, "HostNotInZone", "host " + h + " is in no Zone"
		}
		c := meta.FindStatusCondition(z.Status.Conditions, typ)
		if c == nil || c.Status != metav1.ConditionTrue {
			return metav1.ConditionFalse, "ZoneNotReady", "zone " + z.Name + " is not ready (" + typ + ")"
		}
		if !slices.Contains(names, z.Name) {
			names = append(names, z.Name)
		}
	}
	return metav1.ConditionTrue, "Zone", "served by zone " + strings.Join(names, ", ")
}

// writeStatus records the children and the observed generation. When obs is nil
// (refused, or checks unavailable) nothing was written and the previous children
// keep serving, so the list is kept.
func (r *SiteReconciler) writeStatus(ctx context.Context, site *authv1.Site, obs *observed) error {
	site.Status.ObservedGeneration = site.Generation
	if obs != nil {
		var ch []authv1.Child
		for _, rl := range obs.rules {
			ch = append(ch, authv1.Child{Kind: "Rule", Name: rl.Name, SpecHash: rl.Annotations[render.SpecHashAnnotation]})
		}
		if obs.ingress != nil {
			ch = append(ch, authv1.Child{Kind: "Ingress", Name: obs.ingress.Name, SpecHash: obs.ingress.Annotations[render.SpecHashAnnotation]})
		}
		if obs.cert != nil {
			ch = append(ch, authv1.Child{Kind: "Certificate", Name: obs.cert.GetName(), SpecHash: obs.cert.GetAnnotations()[render.SpecHashAnnotation]})
		}
		site.Status.Children = ch
	}
	return r.Status().Update(ctx, site)
}
