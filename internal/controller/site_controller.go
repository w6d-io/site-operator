// Package controller reconciles Zones into a wildcard Ingress (+ Certificate)
// and Sites into maester Rules (+ an opt-in vanity Ingress/Certificate).
package controller

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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
	"github.com/w6d-io/site-operator/internal/gateway"
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
	// Loaded probes the gateway pods for RulesLoaded; nil skips the check.
	Loaded LoadChecker

	clock loadClock
}

// observed is what the reconcile saw of the children, for the status.
type observed struct {
	rules    []*okv1.Rule
	ingress  *networkingv1.Ingress
	cert     *unstructured.Unstructured
	zones    []authv1.Zone
	conflict string
	// hostTaken names another Ingress serving one of the Site's Ingress hosts.
	hostTaken string
	// shadowed lists wildcard Ingresses elsewhere whose paths the Site's exact-host
	// Ingress overrides for its hosts (a warning, not a refusal).
	shadowed []string
	// ownIngress: the Site has its own Ingress (vanity) or per-host Ingresses (hosts under per-site Zones).
	ownIngress bool
	// hostIngresses are the shared per-host Ingresses serving the Site's hosts.
	hostIngresses []*networkingv1.Ingress
	// routed: some host is under a Zone with a gateway; routes are its HTTPRoutes.
	routed bool
	routes []*unstructured.Unstructured
	// routeTaken names what already serves one of the Site's routed hosts.
	routeTaken string
	// routeRefused: a host's Zone has a gateway the operator may not use.
	routeRefused string
}

func (r *SiteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	site := &authv1.Site{}
	if err := r.Get(ctx, req.NamespacedName, site); err != nil {
		if apierrors.IsNotFound(err) {
			r.clock.forget(req.NamespacedName)
			return ctrl.Result{}, r.release(ctx, req.Namespace, req.Name)
		}
		return ctrl.Result{}, err
	}
	if !site.DeletionTimestamp.IsZero() {
		r.clock.forget(req.NamespacedName)
		// ownerReferences garbage-collect the children; shared host Ingresses and routes lose this owner
		return ctrl.Result{}, r.release(ctx, req.Namespace, req.Name)
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

	obs, err := r.apply(ctx, kids, site, desired, zones.Items)
	if errors.Is(err, errDeleting) {
		return ctrl.Result{RequeueAfter: deletingRetry}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	obs.zones = zones.Items
	setChildConditions(site, desired, obs)
	recheck := r.setRulesLoaded(ctx, site, desired)
	setReady(site)
	if site.Spec.Paused {
		setCondition(site, authv1.ConditionReady, metav1.ConditionFalse, "Paused", "site is paused; visitors get the paused page")
	}
	if err := r.writeStatus(ctx, site, obs); err != nil {
		if apierrors.IsConflict(err) {
			// our cached Site is older than our last status write; the newer
			// version's watch event (or the recheck) reconciles again
			return ctrl.Result{RequeueAfter: recheck}, nil
		}
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: recheck}, nil
}

// validate runs the static checks and gatekit on the rendered gate Rules. It
// returns the Rules to write, or nil after recording a refusal in the status.
func (r *SiteReconciler) validate(ctx context.Context, site *authv1.Site, zones []authv1.Zone) ([]*okv1.Rule, ctrl.Result, error) {
	cfg, err := r.enabledConfig(ctx, site.Namespace)
	if err != nil {
		return nil, ctrl.Result{}, err
	}
	if ref := validate.Static(site, cfg, zones); ref != nil {
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
	var obs *observed
	if ref.Reason == validate.ReasonZoneNotOwned {
		if err := r.withdraw(ctx, site); err != nil {
			return err
		}
		obs = &observed{}
		for _, t := range readyInputs[1:] {
			setCondition(site, t, metav1.ConditionFalse, ref.Reason, "withdrawn: the host's zone is not this operator's")
		}
	}
	setReady(site)
	return r.writeStatus(ctx, site, obs)
}

// withdraw removes everything the Site wrote earlier. Other refusals keep the previous children
// serving (a bad edit must not take a site down); a host under another release's Zone must not keep
// serving from this one, whatever it was before the zone left --zones.
func (r *SiteReconciler) withdraw(ctx context.Context, site *authv1.Site) error {
	if err := r.pruneRules(ctx, site, nil); err != nil {
		return err
	}
	if err := r.pruneExposure(ctx, children{r.Client, r.Recorder}, site, false, false); err != nil {
		return err
	}
	return r.release(ctx, site.Namespace, site.Name)
}

// enabledConfig is the operator config with the handler sets of the Gateway:
// those live on every pod (status.enabled) that the spec still enables, so a
// Site can neither use a handler before its rollout nor one being disabled.
// Without a rolled-out Gateway the flags apply.
func (r *SiteReconciler) enabledConfig(ctx context.Context, ns string) (*config.Config, error) {
	gw := &authv1.Gateway{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: authv1.GatewayName}, gw); err != nil {
		return r.Config, client.IgnoreNotFound(err)
	}
	live := gw.Status.Enabled
	if live == nil {
		return r.Config, nil
	}
	want := gateway.Enabled(&gw.Spec)
	both := func(a, b []string) []string {
		var out []string
		for _, h := range a {
			if slices.Contains(b, h) {
				out = append(out, h)
			}
		}
		return out
	}
	c := *r.Config
	c.EnabledAuthenticators = both(live.Authenticators, want.Authenticators)
	c.EnabledAuthorizers = both(live.Authorizers, want.Authorizers)
	c.EnabledMutators = both(live.Mutators, want.Mutators)
	c.EnabledErrors = both(live.Errors, want.Errors)
	return &c, nil
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
func (r *SiteReconciler) apply(ctx context.Context, kids children, site *authv1.Site, desired []*okv1.Rule, zones []authv1.Zone) (*observed, error) {
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

	// the Gateway entry point first, so a Zone dropping its Ingress keeps serving
	routed, routeZones, refused := routeHosts(site, zones, r.Config)
	obs.routed, obs.routeRefused = len(routed) > 0 || refused != "", refused
	if err := r.hostRoutes(ctx, site, routed, routeZones, obs); err != nil {
		return nil, err
	}
	exp := site.Spec.Exposure
	hosts, hostZones := ingressHosts(site, zones)
	obs.ownIngress = len(hosts) > 0
	// a vanity Site whose hosts are all under ingress-none Zones gets no Ingress
	vanity := exp.Vanity() && obs.ownIngress
	perSite := vanity && exp.TLS == authv1.TLSPerSite
	if vanity {
		if err := r.vanityIngress(ctx, kids, site, hosts, obs); err != nil {
			return nil, err
		}
	} else if err := r.hostIngresses(ctx, site, hosts, hostZones, obs); err != nil {
		return nil, err
	}
	if len(obs.shadowed) > 0 {
		c := meta.FindStatusCondition(site.Status.Conditions, authv1.ConditionHostShadowsWildcard)
		if c == nil || c.Status != metav1.ConditionTrue || c.Message != strings.Join(obs.shadowed, "; ") {
			r.Recorder.Event(site, "Warning", "WildcardShadowed", strings.Join(obs.shadowed, "; "))
		}
	}
	// after the host Ingresses exist, so a Site moving off its own Ingress keeps serving
	if err := r.pruneExposure(ctx, kids, site, vanity, perSite); err != nil {
		return nil, err
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

// release drops a gone Site from the owners of its shared host Ingresses and routes.
func (r *SiteReconciler) release(ctx context.Context, ns, name string) error {
	if err := r.releaseHosts(ctx, ns, name, nil); err != nil || !r.Config.EnableGatewayAPI {
		return err
	}
	return r.releaseRoutes(ctx, ns, name, nil)
}

// vanityIngress writes the Site's own site-<name> Ingress (every host), unless
// another Ingress serves one of them exactly (an existing one is kept).
func (r *SiteReconciler) vanityIngress(ctx context.Context, kids children, site *authv1.Site, hosts []string, obs *observed) error {
	want := render.Ingress(site, r.Config)
	taken, shadowed, err := r.hostCheck(ctx, site, hosts)
	if err != nil {
		return err
	}
	obs.hostTaken, obs.shadowed = taken, appendNew(obs.shadowed, shadowed...)
	existing := &networkingv1.Ingress{}
	err = r.Get(ctx, client.ObjectKeyFromObject(want), existing)
	if client.IgnoreNotFound(err) != nil {
		return err
	}
	switch {
	case taken != "" && err != nil: // not found: nothing created
	case taken != "":
		if metav1.IsControlledBy(existing, site) {
			obs.ingress = existing
		}
	default:
		ing, err := kids.ingress(ctx, site, want)
		if errors.Is(err, errConflict) {
			obs.conflict = "Ingress " + render.IngressName(site)
		} else if err != nil {
			return err
		}
		obs.ingress = ing
	}
	return nil
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
	// a change with the same templates (routes, upstream, ...) is updated in place;
	// the same spec hash means someone edited our Rule: put the rendered spec back.
	// Status (maester's acknowledgement) and finalizers are kept.
	reason, msg := "RuleUpdated", "updated Rule %s in place"
	if got.Annotations[render.SpecHashAnnotation] == want.Annotations[render.SpecHashAnnotation] {
		reason, msg = "RuleRestored", "restored Rule %s to the rendered spec"
	}
	got.Spec, got.Labels, got.Annotations = want.Spec, want.Labels, want.Annotations
	if err := r.Update(ctx, got); err != nil {
		return nil, err
	}
	r.Recorder.Eventf(site, "Normal", reason, msg, want.Name)
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
// valid or invalid, zone readiness feeds the Site conditions) or the Gateway
// changes (enabled handlers).
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
		Watches(&authv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.sitesForZone)).
		Watches(&networkingv1.Ingress{}, handler.EnqueueRequestsFromMapFunc(r.sitesForIngress)).
		Named("site")
	if r.Config.EnableCertificates {
		cert := &unstructured.Unstructured{}
		cert.SetGroupVersionKind(render.CertificateGVK)
		b = b.Owns(cert)
	}
	if r.Config.EnableGatewayAPI {
		// host routes are owned by Sites (not controlled) and foreign routes and
		// listeners take hosts: all are mapped by hostname; a Gateway change
		// (listeners) re-checks every Site
		rt := &unstructured.Unstructured{}
		rt.SetGroupVersionKind(render.HTTPRouteGVK)
		ls := &unstructured.Unstructured{}
		ls.SetGroupVersionKind(render.ListenerSetGVK)
		gw := &unstructured.Unstructured{}
		gw.SetGroupVersionKind(render.GatewayGVK)
		b = b.Watches(rt, handler.EnqueueRequestsFromMapFunc(r.sitesForRoute)).
			Watches(ls, handler.EnqueueRequestsFromMapFunc(r.sitesForListenerSet)).
			Watches(gw, handler.EnqueueRequestsFromMapFunc(r.sitesForZone))
	}
	return b.Complete(r)
}
