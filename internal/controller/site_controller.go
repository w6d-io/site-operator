// Package controller reconciles Zones into a wildcard Ingress (+ Certificate)
// and Sites into maester Rules (+ an opt-in vanity Ingress/Certificate).
package controller

import (
	"context"
	"errors"
	"slices"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
	"github.com/w6d-io/site-operator/internal/render"
	"github.com/w6d-io/site-operator/internal/validate"
)

const (
	// ValidatorRetry is how long to wait before re-checking when gatekit is unavailable.
	ValidatorRetry = 30 * time.Second
	// deletingRetry waits for maester to release a Rule that is being deleted.
	deletingRetry = time.Second
)

// errDeleting marks a desired Rule name still held by a Rule being deleted.
var errDeleting = errors.New("rule is being deleted")

// SiteReconciler reconciles Site objects.
type SiteReconciler struct {
	client.Client
	Config    *config.Config
	Validator validate.Validator
	Recorder  record.EventRecorder
}

// observed is what the reconcile saw of the children, for the status.
type observed struct {
	rules    []*okv1.Rule
	ingress  *networkingv1.Ingress
	cert     *unstructured.Unstructured
	zones    []authv1.Zone
	conflict string
}

func (r *SiteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	site := &authv1.Site{}
	if err := r.Get(ctx, req.NamespacedName, site); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !site.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil // ownerReferences garbage-collect the children
	}
	kids := children{r.Client, r.Recorder}

	var zones authv1.ZoneList
	if err := r.List(ctx, &zones); err != nil {
		return ctrl.Result{}, err
	}
	var desired []*okv1.Rule
	if site.Spec.Paused {
		// pausing must work even when gatekit is down: the deny Rules are fixed
		if ref := validate.Hosts(site, r.Config, zones.Items); ref != nil {
			return ctrl.Result{}, r.refuse(ctx, site, ref)
		}
		desired = render.PausedRules(site, r.Config)
		setCondition(site, authv1.ConditionValidated, metav1.ConditionTrue, "Paused", "paused: every host answers with the paused deny rule")
	} else {
		var res ctrl.Result
		var err error
		if desired, res, err = r.validate(ctx, site, zones.Items); desired == nil {
			return res, err
		}
	}

	obs, err := r.apply(ctx, kids, site, desired)
	if errors.Is(err, errDeleting) {
		return ctrl.Result{RequeueAfter: deletingRetry}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	obs.zones = zones.Items
	setChildConditions(site, desired, obs)
	if site.Spec.Paused {
		setCondition(site, authv1.ConditionReady, metav1.ConditionFalse, "Paused", "site is paused; visitors get the paused page")
	}
	return ctrl.Result{}, r.writeStatus(ctx, site, obs)
}

// validate runs the static checks and gatekit on the rendered gate Rules. It
// returns the Rules to write, or nil after recording a refusal in the status.
func (r *SiteReconciler) validate(ctx context.Context, site *authv1.Site, zones []authv1.Zone) ([]*okv1.Rule, ctrl.Result, error) {
	if ref := validate.Static(site, r.Config, zones); ref != nil {
		return nil, ctrl.Result{}, r.refuse(ctx, site, ref)
	}
	desired := render.Rules(site, r.Config)
	others, err := r.otherRules(ctx, site)
	if err != nil {
		return nil, ctrl.Result{}, err
	}
	candidate := make([]render.OathkeeperRule, 0, len(desired))
	for _, rule := range desired {
		candidate = append(candidate, render.ToOathkeeper(rule))
	}
	if err := r.Validator.Validate(ctx, candidate, others); err != nil {
		var ref *validate.Refusal
		if errors.As(err, &ref) {
			return nil, ctrl.Result{}, r.refuse(ctx, site, ref)
		}
		log.FromContext(ctx).Error(err, "validator unavailable, nothing written")
		setCondition(site, authv1.ConditionValidated, metav1.ConditionUnknown, validate.ReasonValidatorUnavailable,
			"checks are unavailable, nothing was changed: "+err.Error())
		setReady(site)
		return nil, ctrl.Result{RequeueAfter: ValidatorRetry}, r.writeStatus(ctx, site, nil)
	}
	setCondition(site, authv1.ConditionValidated, metav1.ConditionTrue, "Valid", "patterns compile and do not overlap")
	return desired, ctrl.Result{}, nil
}

func (r *SiteReconciler) refuse(ctx context.Context, site *authv1.Site, ref *validate.Refusal) error {
	r.Recorder.Event(site, "Warning", ref.Reason, ref.Message)
	setCondition(site, authv1.ConditionValidated, metav1.ConditionFalse, ref.Reason, ref.Message)
	setReady(site)
	return r.writeStatus(ctx, site, nil)
}

// otherRules returns every live Rule in the namespace that this Site does not own.
func (r *SiteReconciler) otherRules(ctx context.Context, site *authv1.Site) ([]render.OathkeeperRule, error) {
	var list okv1.RuleList
	if err := r.List(ctx, &list, client.InNamespace(site.Namespace)); err != nil {
		return nil, err
	}
	var out []render.OathkeeperRule
	for i := range list.Items {
		if !metav1.IsControlledBy(&list.Items[i], site) && !render.Retired(&list.Items[i]) {
			out = append(out, render.ToOathkeeper(&list.Items[i]))
		}
	}
	return out, nil
}

// apply writes the desired children. Rule swap order (see README "Rule swaps"):
// 1. retire every Rule no longer wanted (its match moves to an unroutable host),
// 2. create the new Rules, 3. delete the retired ones. Watchers (maester) see
// the retirement before the replacement, so two live Rules never match one URL.
func (r *SiteReconciler) apply(ctx context.Context, kids children, site *authv1.Site, desired []*okv1.Rule) (*observed, error) {
	keep := make([]string, 0, len(desired))
	for _, want := range desired {
		keep = append(keep, want.Name)
	}
	if err := r.retireRules(ctx, site, keep); err != nil {
		return nil, err
	}
	obs := &observed{}
	for _, want := range desired {
		got, err := r.applyRule(ctx, site, want)
		if errors.Is(err, errConflict) {
			obs.conflict = "Rule " + want.Name
			continue
		}
		if err != nil {
			return nil, err
		}
		obs.rules = append(obs.rules, got)
	}
	if err := r.pruneRules(ctx, site, keep); err != nil {
		return nil, err
	}

	exp := site.Spec.Exposure
	perSite := exp.Vanity() && exp.TLS == authv1.TLSPerSite
	if err := r.pruneExposure(ctx, kids, site, exp.Vanity(), perSite); err != nil {
		return nil, err
	}
	if exp.Vanity() {
		ing, err := kids.ingress(ctx, site, render.Ingress(site, r.Config))
		if errors.Is(err, errConflict) {
			obs.conflict = "Ingress " + render.IngressName(site)
		} else if err != nil {
			return nil, err
		}
		obs.ingress = ing
	}
	if perSite {
		cert, err := kids.certificate(ctx, site, render.Certificate(site, r.Config))
		if errors.Is(err, errConflict) {
			obs.conflict = "Certificate " + render.IngressName(site)
		} else if err != nil {
			return nil, err
		}
		obs.cert = cert
	}
	return obs, nil
}

func (r *SiteReconciler) applyRule(ctx context.Context, site *authv1.Site, want *okv1.Rule) (*okv1.Rule, error) {
	got := &okv1.Rule{}
	err := r.Get(ctx, client.ObjectKeyFromObject(want), got)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, want); err != nil {
			return nil, err
		}
		r.Recorder.Eventf(site, "Normal", "RuleCreated", "created Rule %s", want.Name)
		return want, nil
	}
	if err != nil {
		return nil, err
	}
	if !metav1.IsControlledBy(got, site) {
		return nil, errConflict
	}
	if !got.DeletionTimestamp.IsZero() {
		return nil, errDeleting // a quick revert to a just-retired name: wait for maester's finalizer
	}
	if render.Hash(got.Spec) == want.Annotations[render.SpecHashAnnotation] && maps(got.Labels, want.Labels) && maps(got.Annotations, want.Annotations) {
		return got, nil
	}
	// someone edited our Rule: put the rendered spec back (status and finalizers kept)
	got.Spec, got.Labels, got.Annotations = want.Spec, want.Labels, want.Annotations
	if err := r.Update(ctx, got); err != nil {
		return nil, err
	}
	r.Recorder.Eventf(site, "Normal", "RuleRestored", "restored Rule %s to the rendered spec", want.Name)
	return got, nil
}

func (r *SiteReconciler) ownedRules(ctx context.Context, site *authv1.Site) ([]*okv1.Rule, error) {
	var list okv1.RuleList
	if err := r.List(ctx, &list, client.InNamespace(site.Namespace), client.MatchingLabels{render.SiteLabel: site.Name}); err != nil {
		return nil, err
	}
	var out []*okv1.Rule
	for i := range list.Items {
		if metav1.IsControlledBy(&list.Items[i], site) {
			out = append(out, &list.Items[i])
		}
	}
	return out, nil
}

// retireRules neutralizes owned Rules whose names are not in keep.
func (r *SiteReconciler) retireRules(ctx context.Context, site *authv1.Site, keep []string) error {
	rules, err := r.ownedRules(ctx, site)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if slices.Contains(keep, rule.Name) || render.Retired(rule) || !rule.DeletionTimestamp.IsZero() {
			continue
		}
		render.Retire(rule)
		if err := r.Update(ctx, rule); err != nil {
			return err
		}
	}
	return nil
}

// pruneRules retires, then deletes, owned Rules whose names are not in keep.
func (r *SiteReconciler) pruneRules(ctx context.Context, site *authv1.Site, keep []string) error {
	if err := r.retireRules(ctx, site, keep); err != nil {
		return err
	}
	rules, err := r.ownedRules(ctx, site)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if slices.Contains(keep, rule.Name) || !rule.DeletionTimestamp.IsZero() {
			continue
		}
		if err := r.Delete(ctx, rule); client.IgnoreNotFound(err) != nil {
			return err
		}
		r.Recorder.Eventf(site, "Normal", "RuleDeleted", "deleted Rule %s", rule.Name)
	}
	return nil
}

func (r *SiteReconciler) pruneExposure(ctx context.Context, kids children, site *authv1.Site, keepIngress, keepCert bool) error {
	key := client.ObjectKey{Namespace: site.Namespace, Name: render.IngressName(site)}
	if !keepIngress {
		if err := kids.deleteIngress(ctx, site, key); err != nil {
			return err
		}
	}
	if !keepCert && r.Config.EnableCertificates {
		return kids.deleteCertificate(ctx, site, key)
	}
	return nil
}

// sitesForZone re-reconciles every Site when a Zone changes (hosts may become
// valid or invalid, zone readiness feeds the Site conditions).
func (r *SiteReconciler) sitesForZone(ctx context.Context, _ client.Object) []reconcile.Request {
	var sites authv1.SiteList
	if err := r.List(ctx, &sites, client.InNamespace(r.Config.GatewayNamespace)); err != nil {
		return nil
	}
	out := make([]reconcile.Request, 0, len(sites.Items))
	for _, s := range sites.Items {
		out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&s)})
	}
	return out
}

// SetupWithManager registers the controller and its owned kinds.
func (r *SiteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	b := ctrl.NewControllerManagedBy(mgr).
		For(&authv1.Site{}).
		Owns(&okv1.Rule{}).
		Owns(&networkingv1.Ingress{}).
		Watches(&authv1.Zone{}, handler.EnqueueRequestsFromMapFunc(r.sitesForZone)).
		Named("site")
	if r.Config.EnableCertificates {
		cert := &unstructured.Unstructured{}
		cert.SetGroupVersionKind(render.CertificateGVK)
		b = b.Owns(cert)
	}
	return b.Complete(r)
}
