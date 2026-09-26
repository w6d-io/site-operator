package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/config"
	"github.com/w6d-io/site-operator/internal/gateway"
	"github.com/w6d-io/site-operator/internal/render"
)

const (
	// ConfigHashAnnotation on the Oathkeeper pod template names the versioned
	// config being rolled out (absent while the chart's seed config serves).
	ConfigHashAnnotation = "auth.w6d.io/gateway-config-hash"
	// GatewayConfigLabel marks the versioned config ConfigMaps the operator owns.
	GatewayConfigLabel = "auth.w6d.io/gateway-config"
	// keptRevisions is how many versioned configs are kept (plus in use and last good).
	keptRevisions = 3

	rolloutPoll = 2 * time.Second
)

// GatewayReconciler renders the Gateway into an immutable, versioned config
// ConfigMap (<prefix>-<hash8>), points the Oathkeeper Deployment's config volume
// at it (a rolling update: pods not yet replaced keep mounting the previous
// one), waits for every pod to be Ready and to serve every Rule, and points the
// volume back at the last good config when the rollout fails.
type GatewayReconciler struct {
	client.Client
	// APIReader reads the base ConfigMap and the Deployment uncached (get by name only).
	APIReader client.Reader
	Config    *config.Config
	Recorder  record.EventRecorder
	// Loaded checks that every gateway pod serves every Rule after a rollout; nil skips it.
	Loaded LoadChecker

	mu       sync.Mutex
	rollouts map[string]time.Time // target ConfigMap → rollout start
}

func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	gw := &authv1.Gateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err) // deleting the Gateway leaves the config as it is
	}
	var rules okv1.RuleList
	if err := r.List(ctx, &rules, client.InNamespace(gw.Namespace)); err != nil {
		return ctrl.Result{}, err
	}
	gw.Status.InUse = gateway.InUse(rules.Items)

	if p := gateway.Validate(&gw.Spec); len(p) > 0 {
		return r.refuse(ctx, gw, "InvalidConfig", "rejected by the Oathkeeper "+gateway.SchemaVersion+" config schema: "+strings.Join(p, "; "))
	}
	if d := gateway.Disabled(&gw.Spec, gw.Status.InUse); len(d) > 0 {
		return r.refuse(ctx, gw, "HandlerInUse", "cannot disable handlers still used by live rules: "+strings.Join(d, "; "))
	}
	setGatewayCondition(gw, authv1.GatewayConditionValidated, metav1.ConditionTrue, "Valid",
		"handler configs match the Oathkeeper "+gateway.SchemaVersion+" config schema")

	base := &corev1.ConfigMap{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: r.Config.GatewayBaseConfigMap}, base); err != nil {
		return r.blocked(ctx, gw, "BaseConfigMissing", err)
	}
	rendered, hash, err := gateway.Render([]byte(base.Data[r.Config.GatewayConfigKey]), &gw.Spec)
	if err != nil {
		return r.refuse(ctx, gw, "BaseConfigInvalid", err.Error())
	}
	dep := &appsv1.Deployment{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: r.Config.GatewayDeployment}, dep); err != nil {
		return r.blocked(ctx, gw, "DeploymentMissing", err)
	}
	current := configVolume(dep, r.Config.GatewayConfigVolume)
	if current == "" {
		return r.blocked(ctx, gw, "ConfigVolumeMissing", apierrors.NewNotFound(corev1.Resource("volume"), r.Config.GatewayConfigVolume))
	}
	if gw.Status.ConfigMap == "" {
		gw.Status.ConfigMap = current // first rollout: what the chart seeded is the rollback target
	}

	// target is what should serve: the rendered revision, or the last good one
	// while the rendered revision is the one that failed (until the spec changes)
	target := r.revision(hash)
	rolledBack := hash == gw.Status.FailedHash
	if rolledBack {
		target = gw.Status.ConfigMap
	} else if err := r.createRevision(ctx, gw, target, hash, rendered); err != nil {
		return ctrl.Result{}, err
	}
	if current != target || dep.Spec.Template.Annotations[ConfigHashAnnotation] != r.hashOf(target) {
		if err := r.point(ctx, dep, target); err != nil {
			return ctrl.Result{}, err
		}
		r.Recorder.Eventf(gw, "Normal", "RolloutStarted", "rolling %s to config %s", dep.Name, target)
		setGatewayCondition(gw, authv1.GatewayConditionRolled, metav1.ConditionFalse, "RollingOut", "rolling "+dep.Name+" to config "+target)
	}
	if rolledBack {
		setGatewayCondition(gw, authv1.GatewayConditionApplied, metav1.ConditionFalse, "RolledBack",
			"config "+hash+" failed to roll out; "+target+" serves until the Gateway changes")
	} else {
		setGatewayCondition(gw, authv1.GatewayConditionApplied, metav1.ConditionTrue, "Written", "config written to "+target)
	}

	done, why := rolled(dep, r.Config.GatewayConfigVolume, target)
	if done {
		setGatewayCondition(gw, authv1.GatewayConditionRolled, metav1.ConditionTrue, "Rolled", why)
		done, why = r.rulesLoaded(ctx, rules.Items)
	} else {
		setGatewayCondition(gw, authv1.GatewayConditionRolled, metav1.ConditionFalse, "RollingOut", why)
	}
	if done {
		return ctrl.Result{}, r.succeeded(ctx, gw, target, rolledBack)
	}
	if r.expired(target) || progressDeadline(dep) {
		if rolledBack || target == gw.Status.ConfigMap {
			// nothing better to go back to: report and keep watching slowly
			setGatewayCondition(gw, authv1.GatewayConditionReady, metav1.ConditionFalse, "RolloutFailed", why)
			return ctrl.Result{RequeueAfter: timedOutRecheck}, r.writeGatewayStatus(ctx, gw)
		}
		return r.rollback(ctx, gw, dep, hash, why)
	}
	setGatewayCondition(gw, authv1.GatewayConditionReady, metav1.ConditionFalse, "RollingOut", why)
	return ctrl.Result{RequeueAfter: rolloutPoll}, r.writeGatewayStatus(ctx, gw)
}

// revision is the versioned ConfigMap name of a rendered config.
func (r *GatewayReconciler) revision(hash string) string {
	return r.Config.GatewayConfigPrefix + "-" + hash
}

// hashOf is the config-hash annotation for a target ConfigMap: its hash for a
// revision, empty for the chart's seed.
func (r *GatewayReconciler) hashOf(name string) string {
	if h, ok := strings.CutPrefix(name, r.Config.GatewayConfigPrefix+"-"); ok && len(h) == 8 {
		return h
	}
	return ""
}

// createRevision creates the immutable ConfigMap of a rendered config (its name
// is its content hash, so an existing one is the same) and records it.
func (r *GatewayReconciler) createRevision(ctx context.Context, gw *authv1.Gateway, name, hash string, cfg []byte) error {
	immutable := true
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gw.Namespace,
			Labels:      map[string]string{render.ManagedByLabel: render.ManagedBy, GatewayConfigLabel: "true"},
			Annotations: map[string]string{ConfigHashAnnotation: hash}},
		Immutable: &immutable,
		Data:      map[string]string{r.Config.GatewayConfigKey: string(cfg)},
	}
	if err := r.Create(ctx, cm); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	gw.Status.Revisions = append([]string{name}, slices.DeleteFunc(gw.Status.Revisions, func(n string) bool { return n == name })...)
	return nil
}

// point sets the Deployment's config volume to target and the config-hash
// annotation to match (a strategic merge: nothing else in the pod template changes).
func (r *GatewayReconciler) point(ctx context.Context, dep *appsv1.Deployment, target string) error {
	r.mu.Lock()
	if r.rollouts == nil {
		r.rollouts = map[string]time.Time{}
	}
	r.rollouts[target] = time.Now()
	r.mu.Unlock()
	hash := "null"
	if h := r.hashOf(target); h != "" {
		hash = fmt.Sprintf("%q", h)
	}
	patch := fmt.Appendf(nil, `{"spec":{"template":{"metadata":{"annotations":{%q:%s}},"spec":{"volumes":[{"name":%q,"configMap":{"name":%q}}]}}}}`,
		ConfigHashAnnotation, hash, r.Config.GatewayConfigVolume, target)
	return r.Patch(ctx, dep, client.RawPatch(types.StrategicMergePatchType, patch))
}

func (r *GatewayReconciler) expired(target string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	start, ok := r.rollouts[target]
	if !ok {
		// operator restarted mid-rollout: the deadline starts now
		if r.rollouts == nil {
			r.rollouts = map[string]time.Time{}
		}
		r.rollouts[target] = time.Now()
		return false
	}
	return time.Since(start) > r.Config.GatewayRolloutTimeout
}

// configVolume is the ConfigMap the Deployment's config volume mounts.
func configVolume(dep *appsv1.Deployment, volume string) string {
	for _, v := range dep.Spec.Template.Spec.Volumes {
		if v.Name == volume && v.ConfigMap != nil {
			return v.ConfigMap.Name
		}
	}
	return ""
}

// rolled reports whether every replica runs the pod template mounting target and is Ready.
func rolled(dep *appsv1.Deployment, volume, target string) (bool, string) {
	want := int32(1)
	if dep.Spec.Replicas != nil {
		want = *dep.Spec.Replicas
	}
	s := dep.Status
	msg := fmt.Sprintf("%d/%d pods updated, %d ready, %d total", s.UpdatedReplicas, want, s.ReadyReplicas, s.Replicas)
	ok := configVolume(dep, volume) == target && s.ObservedGeneration >= dep.Generation &&
		s.UpdatedReplicas == want && s.ReadyReplicas == want && s.AvailableReplicas == want && s.Replicas == want
	return ok, msg
}

func progressDeadline(dep *appsv1.Deployment) bool {
	for _, c := range dep.Status.Conditions {
		if c.Type == appsv1.DeploymentProgressing && c.Status == corev1.ConditionFalse && c.Reason == "ProgressDeadlineExceeded" {
			return true
		}
	}
	return false
}

// rulesLoaded checks that every gateway pod serves every live, acknowledged
// Rule: a handler config Oathkeeper rejects drops the Rules using it.
func (r *GatewayReconciler) rulesLoaded(ctx context.Context, rules []okv1.Rule) (bool, string) {
	if r.Loaded == nil {
		return true, "pods Ready (loaded rules not checked)"
	}
	want := map[string]string{}
	for i := range rules {
		rl := &rules[i]
		v := rl.Status.Validation
		if !rl.DeletionTimestamp.IsZero() || v == nil || v.Valid == nil || !*v.Valid {
			continue
		}
		o := render.ToOathkeeper(rl)
		want[o.ID] = o.Match.URL
	}
	if len(want) == 0 {
		return true, "pods Ready (no rules to check)"
	}
	rep, err := r.Loaded.Check(ctx, want)
	if err != nil {
		return false, err.Error()
	}
	return rep.Done(), rep.String()
}

func (r *GatewayReconciler) succeeded(ctx context.Context, gw *authv1.Gateway, target string, rolledBack bool) error {
	gw.Status.ConfigMap, gw.Status.ConfigHash = target, r.hashOf(target)
	if rolledBack {
		setGatewayCondition(gw, authv1.GatewayConditionReady, metav1.ConditionFalse, "RolledBack",
			"the previous config serves on every pod; the Gateway spec is not applied")
	} else {
		enabled := gateway.Enabled(&gw.Spec)
		gw.Status.Enabled, gw.Status.FailedHash = &enabled, ""
		setGatewayCondition(gw, authv1.GatewayConditionReady, metav1.ConditionTrue, "Ready", "config "+target+" serves on every pod with every rule loaded")
	}
	if err := r.prune(ctx, gw, target); err != nil {
		return err
	}
	return r.writeGatewayStatus(ctx, gw)
}

// prune deletes the revisions beyond the newest keptRevisions, never the one in
// use or the last good one.
func (r *GatewayReconciler) prune(ctx context.Context, gw *authv1.Gateway, inUse string) error {
	var kept []string
	for i, name := range gw.Status.Revisions {
		if i < keptRevisions || name == inUse || name == gw.Status.ConfigMap {
			kept = append(kept, name)
			continue
		}
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gw.Namespace}}
		if err := r.Delete(ctx, cm); client.IgnoreNotFound(err) != nil {
			return err
		}
		r.Recorder.Eventf(gw, "Normal", "RevisionDeleted", "deleted old config %s", name)
	}
	gw.Status.Revisions = kept
	return nil
}

func (r *GatewayReconciler) rollback(ctx context.Context, gw *authv1.Gateway, dep *appsv1.Deployment, failed, why string) (ctrl.Result, error) {
	good := gw.Status.ConfigMap
	if err := r.point(ctx, dep, good); err != nil {
		return ctrl.Result{}, err
	}
	msg := "config " + r.revision(failed) + " did not roll out in time (" + why + "); pointed back to " + good
	r.Recorder.Event(gw, "Warning", "RolledBack", msg)
	gw.Status.FailedHash = failed
	setGatewayCondition(gw, authv1.GatewayConditionApplied, metav1.ConditionFalse, "RolledBack", msg)
	setGatewayCondition(gw, authv1.GatewayConditionRolled, metav1.ConditionFalse, "RolledBack", msg)
	setGatewayCondition(gw, authv1.GatewayConditionReady, metav1.ConditionFalse, "RolledBack", msg)
	return ctrl.Result{RequeueAfter: rolloutPoll}, r.writeGatewayStatus(ctx, gw)
}

// refuse records a spec the operator will not apply; nothing is written.
func (r *GatewayReconciler) refuse(ctx context.Context, gw *authv1.Gateway, reason, msg string) (ctrl.Result, error) {
	r.Recorder.Event(gw, "Warning", reason, msg)
	setGatewayCondition(gw, authv1.GatewayConditionValidated, metav1.ConditionFalse, reason, msg)
	setGatewayCondition(gw, authv1.GatewayConditionReady, metav1.ConditionFalse, reason, "nothing was changed: "+msg)
	return ctrl.Result{}, r.writeGatewayStatus(ctx, gw)
}

// blocked records a missing platform object (chart not installed yet) and retries.
func (r *GatewayReconciler) blocked(ctx context.Context, gw *authv1.Gateway, reason string, err error) (ctrl.Result, error) {
	if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	setGatewayCondition(gw, authv1.GatewayConditionApplied, metav1.ConditionFalse, reason, err.Error())
	setGatewayCondition(gw, authv1.GatewayConditionReady, metav1.ConditionFalse, reason, err.Error())
	return ctrl.Result{RequeueAfter: timedOutRecheck}, r.writeGatewayStatus(ctx, gw)
}

func setGatewayCondition(gw *authv1.Gateway, typ string, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
		Type: typ, Status: status, Reason: reason, Message: msg, ObservedGeneration: gw.Generation,
	})
}

func (r *GatewayReconciler) writeGatewayStatus(ctx context.Context, gw *authv1.Gateway) error {
	gw.Status.ObservedGeneration = gw.Generation
	err := r.Status().Update(ctx, gw)
	if apierrors.IsConflict(err) {
		return nil // a newer Gateway is queued
	}
	return err
}

// gatewayForRule re-reconciles the Gateway when Rules change (handlers in use).
func (r *GatewayReconciler) gatewayForRule(_ context.Context, obj client.Object) []reconcile.Request {
	return []reconcile.Request{{NamespacedName: client.ObjectKey{Namespace: obj.GetNamespace(), Name: authv1.GatewayName}}}
}

// SetupWithManager registers the Gateway controller.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authv1.Gateway{}).
		Watches(&okv1.Rule{}, handler.EnqueueRequestsFromMapFunc(r.gatewayForRule)).
		Named("gateway").
		Complete(r)
}
