package controller

import (
	"context"
	"errors"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
	"github.com/w6d-io/site-operator/internal/render"
)

// Keys of the mirrored ConfigMap read by the admission policies: the Zone
// domains, and the Zone TLS Secrets a per-site Ingress may use.
const (
	ZonesDomainsKey = "domains"
	ZonesSecretsKey = "secrets"
)

// ZoneReconciler renders one wildcard Ingress (+ Certificate) per Zone and
// mirrors the Zone domains into a ConfigMap for the admission policy.
type ZoneReconciler struct {
	client.Client
	// APIReader reads the mirror ConfigMap uncached (the operator may not list ConfigMaps).
	APIReader client.Reader
	Config    *config.Config
	Recorder  record.EventRecorder
}

func (r *ZoneReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var all authv1.ZoneList
	if err := r.List(ctx, &all); err != nil {
		return ctrl.Result{}, err
	}
	mirrorErr := r.mirror(ctx, all.Items)

	zone := &authv1.Zone{}
	if err := r.Get(ctx, req.NamespacedName, zone); err != nil {
		return ctrl.Result{}, errors.Join(client.IgnoreNotFound(err), mirrorErr)
	}
	if !zone.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, mirrorErr
	}
	kids := children{r.Client, r.Recorder}
	key := client.ObjectKey{Namespace: r.Config.GatewayNamespace, Name: render.ZoneName(zone)}

	if reason, msg := r.check(zone, all.Items); reason != "" {
		r.Recorder.Event(zone, "Warning", reason, msg)
		setZoneCondition(zone, authv1.ConditionValidated, metav1.ConditionFalse, reason, msg)
		setZoneCondition(zone, authv1.ConditionReady, metav1.ConditionFalse, reason, msg)
		return ctrl.Result{}, errors.Join(r.writeStatus(ctx, zone), mirrorErr)
	}
	setZoneCondition(zone, authv1.ConditionValidated, metav1.ConditionTrue, "Valid", "zone settings are allowed")

	if zone.Spec.PerSite() {
		// no wildcard: each Site gets its own exact-host Ingress (after a cluster-wide host check)
		if err := kids.deleteIngress(ctx, zone, key); err != nil {
			return ctrl.Result{}, err
		}
		setZoneCondition(zone, authv1.ConditionIngressReady, metav1.ConditionTrue, "PerSite",
			"no wildcard Ingress: each Site gets its own exact-host Ingress")
		if err := r.certificate(ctx, kids, zone, key); err != nil {
			return ctrl.Result{}, err
		}
		setZoneReady(zone)
		return ctrl.Result{}, errors.Join(r.writeStatus(ctx, zone), mirrorErr)
	}
	ing, err := kids.ingress(ctx, zone, render.ZoneIngress(zone, r.Config))
	switch {
	case errors.Is(err, errConflict):
		setZoneCondition(zone, authv1.ConditionIngressReady, metav1.ConditionFalse, "NameConflict", "Ingress "+key.Name+" "+errConflict.Error())
	case err != nil:
		return ctrl.Result{}, err
	case lbAddress(ing) == "":
		setZoneCondition(zone, authv1.ConditionIngressReady, metav1.ConditionFalse, "WaitingForAddress", "the ingress controller has not admitted the wildcard Ingress yet")
	default:
		setZoneCondition(zone, authv1.ConditionIngressReady, metav1.ConditionTrue, "Admitted", "load balancer "+lbAddress(ing))
	}

	if err := r.certificate(ctx, kids, zone, key); err != nil {
		return ctrl.Result{}, err
	}
	setZoneReady(zone)
	return ctrl.Result{}, errors.Join(r.writeStatus(ctx, zone), mirrorErr)
}

// check refuses Zone settings outside the operator config, and a domain that an
// older Zone already claims (oldest wins).
func (r *ZoneReconciler) check(zone *authv1.Zone, all []authv1.Zone) (string, string) {
	if cls := render.ZoneIngressClass(zone, r.Config); !slices.Contains(r.Config.IngressClasses, cls) {
		return "IngressClassNotAllowed", "ingress class " + cls + " is not allowed"
	}
	if zone.Spec.TLS.Mode == authv1.ZoneTLSIssuer {
		if !r.Config.EnableCertificates {
			return "CertificatesDisabled", "certificates are disabled on this operator"
		}
		if iss := render.ZoneIssuer(zone, r.Config); !slices.Contains(r.Config.Issuers, iss) {
			return "IssuerNotAllowed", "issuer " + iss + " is not allowed"
		}
	}
	for _, o := range all {
		if o.Name != zone.Name && o.Spec.Domain == zone.Spec.Domain && o.CreationTimestamp.Before(&zone.CreationTimestamp) {
			return "DomainTaken", "domain " + zone.Spec.Domain + " already belongs to zone " + o.Name
		}
	}
	return "", ""
}

func (r *ZoneReconciler) certificate(ctx context.Context, kids children, zone *authv1.Zone, key client.ObjectKey) error {
	if zone.Spec.TLS.Mode != authv1.ZoneTLSIssuer {
		if r.Config.EnableCertificates {
			if err := kids.deleteCertificate(ctx, zone, key); err != nil {
				return err
			}
		}
		msg := "the ingress controller default certificate serves the zone"
		if zone.Spec.TLS.Mode == authv1.ZoneTLSSecret {
			msg = "served with Secret " + zone.Spec.TLS.SecretName
		}
		setZoneCondition(zone, authv1.ConditionCertificateReady, metav1.ConditionTrue, "NotRequired", msg)
		return nil
	}
	cert, err := kids.certificate(ctx, zone, render.ZoneCertificate(zone, r.Config))
	if errors.Is(err, errConflict) {
		setZoneCondition(zone, authv1.ConditionCertificateReady, metav1.ConditionFalse, "NameConflict", "Certificate "+key.Name+" "+errConflict.Error())
		return nil
	}
	if err != nil {
		return err
	}
	if ok, reason, msg := certReady(cert); ok {
		setZoneCondition(zone, authv1.ConditionCertificateReady, metav1.ConditionTrue, "Issued", msg)
	} else {
		setZoneCondition(zone, authv1.ConditionCertificateReady, metav1.ConditionFalse, reason, msg)
	}
	return nil
}

// mirror writes the sorted Zone domains into the pre-created ConfigMap. The
// operator may only get/update that one ConfigMap (RBAC resourceNames).
func (r *ZoneReconciler) mirror(ctx context.Context, zones []authv1.Zone) error {
	var domains, secrets []string
	for i := range zones {
		z := &zones[i]
		if !z.DeletionTimestamp.IsZero() {
			continue
		}
		if !slices.Contains(domains, z.Spec.Domain) {
			domains = append(domains, z.Spec.Domain)
		}
		if s := render.ZoneSecret(z); s != "" && !slices.Contains(secrets, s) {
			secrets = append(secrets, s)
		}
	}
	slices.Sort(domains)
	slices.Sort(secrets)
	want := map[string]string{ZonesDomainsKey: strings.Join(domains, ","), ZonesSecretsKey: strings.Join(secrets, ",")}
	cm := &corev1.ConfigMap{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: r.Config.GatewayNamespace, Name: r.Config.ZonesConfigMap}, cm); err != nil {
		if apierrors.IsNotFound(err) {
			return errors.New("zones ConfigMap " + r.Config.ZonesConfigMap + " is missing; it is created by the deploy manifests")
		}
		return err
	}
	if cm.Data[ZonesDomainsKey] == want[ZonesDomainsKey] && cm.Data[ZonesSecretsKey] == want[ZonesSecretsKey] {
		return nil
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	for k, v := range want {
		cm.Data[k] = v
	}
	return r.Update(ctx, cm)
}

func setZoneCondition(z *authv1.Zone, typ string, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&z.Status.Conditions, metav1.Condition{
		Type: typ, Status: status, Reason: reason, Message: msg, ObservedGeneration: z.Generation,
	})
}

func setZoneReady(z *authv1.Zone) {
	for _, t := range []string{authv1.ConditionIngressReady, authv1.ConditionCertificateReady} {
		if c := meta.FindStatusCondition(z.Status.Conditions, t); c == nil || c.Status != metav1.ConditionTrue {
			reason, msg := t+"Pending", t+" not evaluated"
			if c != nil {
				reason, msg = c.Reason, t+": "+c.Message
			}
			setZoneCondition(z, authv1.ConditionReady, metav1.ConditionFalse, reason, msg)
			return
		}
	}
	msg := "wildcard Ingress admitted and certificate in place"
	if z.Spec.PerSite() {
		msg = "per-site Ingresses; certificate in place"
	}
	setZoneCondition(z, authv1.ConditionReady, metav1.ConditionTrue, "Ready", msg)
}

func (r *ZoneReconciler) writeStatus(ctx context.Context, z *authv1.Zone) error {
	z.Status.ObservedGeneration = z.Generation
	return r.Status().Update(ctx, z)
}

// zoneForChild maps a zone-<name> Ingress/Certificate back to its Zone.
func zoneForChild(_ context.Context, o client.Object) []reconcile.Request {
	if z := o.GetLabels()[render.ZoneLabel]; z != "" {
		return []reconcile.Request{{NamespacedName: client.ObjectKey{Name: z}}}
	}
	return nil
}

// SetupWithManager registers the controller. Children live in the gateway
// namespace with a cluster-scoped owner, so they are mapped by label.
func (r *ZoneReconciler) SetupWithManager(mgr ctrl.Manager) error {
	b := ctrl.NewControllerManagedBy(mgr).
		For(&authv1.Zone{}).
		Watches(&networkingv1.Ingress{}, handler.EnqueueRequestsFromMapFunc(zoneForChild)).
		Named("zone")
	if r.Config.EnableCertificates {
		cert := &unstructured.Unstructured{}
		cert.SetGroupVersionKind(render.CertificateGVK)
		b = b.Watches(cert, handler.EnqueueRequestsFromMapFunc(zoneForChild))
	}
	return b.Complete(r)
}
