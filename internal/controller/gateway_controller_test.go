package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/validate"
)

const baseConfig = `log: {level: info, format: json}
serve:
  proxy: {port: 4455, trust_forwarded_headers: true}
  api: {port: 4456}
access_rules:
  matching_strategy: regexp
  repositories: [file:///etc/rules/access-rules.json]
authenticators:
  noop: {enabled: true}
`

const seedConfigMap = "auth-oathkeeper-config"

// setupGatewayPlatform creates what the chart ships: the base config, a seed
// config the Deployment mounts before any Gateway, the Oathkeeper Deployment,
// and one of its pods (envtest runs no controllers: the pod is a record of what
// a running pod mounts).
func setupGatewayPlatform(ctx context.Context) error {
	two := int32(2)
	labels := map[string]string{"app.kubernetes.io/name": "oathkeeper"}
	podSpec := corev1.PodSpec{
		Containers: []corev1.Container{{Name: "oathkeeper", Image: "oryd/oathkeeper:v25.4.0",
			VolumeMounts: []corev1.VolumeMount{{Name: cfg.GatewayConfigVolume, MountPath: "/etc/config"}, {Name: "rules", MountPath: "/etc/rules"}}}},
		Volumes: []corev1.Volume{
			{Name: cfg.GatewayConfigVolume, VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: seedConfigMap}}}},
			{Name: "rules", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		},
	}
	for _, o := range []client.Object{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cfg.GatewayBaseConfigMap, Namespace: "auth"}, Data: map[string]string{"config.yaml": baseConfig}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: seedConfigMap, Namespace: "auth"}, Data: map[string]string{"config.yaml": baseConfig}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: cfg.GatewayDeployment, Namespace: "auth"},
			Spec: appsv1.DeploymentSpec{Replicas: &two, Selector: &metav1.LabelSelector{MatchLabels: labels},
				Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: podSpec}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "auth-oathkeeper-old", Namespace: "auth", Labels: labels}, Spec: podSpec},
	} {
		if err := k8s.Create(ctx, o); err != nil {
			return err
		}
	}
	return nil
}

// platformGateway enables what the Site tests use (and not bearer_token).
func platformGateway() authv1.GatewaySpec {
	on := func(c string) authv1.GatewayHandler {
		h := authv1.GatewayHandler{Enabled: true}
		if c != "" {
			h.Config = raw(c)
		}
		return h
	}
	return authv1.GatewaySpec{
		Authenticators: map[string]authv1.GatewayHandler{
			"noop":           on(""),
			"cookie_session": on(`{"check_session_url":"http://kratos-public.auth/sessions/whoami"}`),
		},
		Authorizers: map[string]authv1.GatewayHandler{
			"allow": on(""), "deny": on(""),
			"remote_json": on(`{"remote":"http://opa-authz-proxy.auth:8080/v1/data/rbac/allow","payload":"{}"}`),
		},
		Mutators: map[string]authv1.GatewayHandler{"noop": on(""), "header": on(`{"headers":{"X-User":"{{ print .Subject }}"}}`)},
		Errors: authv1.GatewayErrors{Handlers: map[string]authv1.GatewayHandler{
			"json": on(`{"verbose":false}`), "redirect": on(`{"to":"https://auth.dev.example.com/login"}`),
		}},
	}
}

func getGateway(t *testing.T) *authv1.Gateway {
	t.Helper()
	g := &authv1.Gateway{}
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "default"}, g); err != nil {
		t.Fatal(err)
	}
	return g
}

func gwCond(t *testing.T, typ string, status metav1.ConditionStatus, reason string) *authv1.Gateway {
	t.Helper()
	var g *authv1.Gateway
	eventually(t, fmt.Sprintf("gateway %s=%s/%s", typ, status, reason), func() error {
		g = getGateway(t)
		c := meta.FindStatusCondition(g.Status.Conditions, typ)
		if g.Status.ObservedGeneration != g.Generation || c == nil || c.ObservedGeneration != g.Generation {
			return fmt.Errorf("generation %d not observed: %+v", g.Generation, g.Status.Conditions)
		}
		if c.Status != status || c.Reason != reason {
			return fmt.Errorf("got %s/%s: %s", c.Status, c.Reason, c.Message)
		}
		return nil
	})
	return g
}

func updateGateway(t *testing.T, f func(*authv1.GatewaySpec)) {
	t.Helper()
	eventually(t, "update gateway", func() error {
		g := getGateway(t)
		f(&g.Spec)
		return k8s.Update(ctx, g)
	})
}

// revisions lists the versioned config ConfigMaps by name.
func revisions(t *testing.T) map[string]*corev1.ConfigMap {
	t.Helper()
	var l corev1.ConfigMapList
	if err := k8s.List(ctx, &l, client.InNamespace("auth"), client.MatchingLabels{GatewayConfigLabel: "true"}); err != nil {
		t.Fatal(err)
	}
	out := map[string]*corev1.ConfigMap{}
	for i := range l.Items {
		out[l.Items[i].Name] = &l.Items[i]
	}
	return out
}

// mounted is the ConfigMap the Deployment's config volume points at.
func mounted(t *testing.T) string {
	t.Helper()
	return configVolume(deployment(t), cfg.GatewayConfigVolume)
}

// waitMounted waits until the Deployment's config volume points at a ConfigMap
// other than those in not, and returns it.
func waitMounted(t *testing.T, not ...string) string {
	t.Helper()
	var m string
	eventually(t, fmt.Sprintf("config volume moves off %v", not), func() error {
		if m = mounted(t); slices.Contains(not, m) {
			return fmt.Errorf("still %s", m)
		}
		return nil
	})
	return m
}

func deployment(t *testing.T) *appsv1.Deployment {
	t.Helper()
	d := &appsv1.Deployment{}
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: cfg.GatewayDeployment}, d); err != nil {
		t.Fatal(err)
	}
	return d
}

// rollDeployment plays the Deployment controller: every replica updated and Ready.
func rollDeployment(t *testing.T, target string) {
	t.Helper()
	eventually(t, "roll deployment to "+target, func() error {
		d := deployment(t)
		if m := configVolume(d, cfg.GatewayConfigVolume); m != target {
			return fmt.Errorf("config volume mounts %q", m)
		}
		d.Status = appsv1.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: 2, UpdatedReplicas: 2, ReadyReplicas: 2, AvailableReplicas: 2}
		return k8s.Status().Update(ctx, d)
	})
}

// oldPodUntouched checks what a pod started before any rollout mounts: its
// volume still names the seed config, which still exists unchanged.
func oldPodUntouched(t *testing.T) {
	t.Helper()
	pod := &corev1.Pod{}
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "auth-oathkeeper-old"}, pod); err != nil {
		t.Fatal(err)
	}
	if pod.Spec.Volumes[0].ConfigMap.Name != seedConfigMap {
		t.Fatalf("old pod mounts %s", pod.Spec.Volumes[0].ConfigMap.Name)
	}
	seed := &corev1.ConfigMap{}
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: seedConfigMap}, seed); err != nil || seed.Data["config.yaml"] != baseConfig {
		t.Fatalf("the config an old pod mounts changed: %v %v", err, seed.Data)
	}
}

// TestGateway walks one Gateway through its life: refusals that write nothing,
// a rolling rollout to a versioned config, a failed rollout pointed back to the
// last good config, Sites validated against the handlers live on the gateway,
// and old revisions pruned.
func TestGateway(t *testing.T) {
	t.Cleanup(func() {
		_ = k8s.Delete(ctx, &authv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "auth"}})
	})
	// a Site whose Rules use cookie_session, remote_json, header
	if err := k8s.Create(ctx, newSite("authors")); err != nil {
		t.Fatal(err)
	}
	twoRules(t, "authors")
	ackRules(t, "authors")
	nothingWritten := func() {
		t.Helper()
		if mounted(t) != seedConfigMap || len(revisions(t)) != 0 || deployment(t).Spec.Template.Annotations[ConfigHashAnnotation] != "" {
			t.Fatal("a refused Gateway must write nothing")
		}
	}

	// invalid handler config: refused, nothing written
	bad := platformGateway()
	bad.Authenticators["cookie_session"] = authv1.GatewayHandler{Enabled: true}
	if err := k8s.Create(ctx, &authv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "auth"}, Spec: bad}); err != nil {
		t.Fatal(err)
	}
	g := gwCond(t, authv1.GatewayConditionValidated, metav1.ConditionFalse, "InvalidConfig")
	if c := meta.FindStatusCondition(g.Status.Conditions, authv1.GatewayConditionValidated); !strings.Contains(c.Message, "authenticators.cookie_session: missing property 'config'") {
		t.Fatalf("message %q", c.Message)
	}
	nothingWritten()

	// disabling a handler a Site uses: refused, with the users
	updateGateway(t, func(s *authv1.GatewaySpec) {
		*s = platformGateway()
		delete(s.Authenticators, "cookie_session")
	})
	g = gwCond(t, authv1.GatewayConditionValidated, metav1.ConditionFalse, "HandlerInUse")
	if c := meta.FindStatusCondition(g.Status.Conditions, authv1.GatewayConditionValidated); !strings.Contains(c.Message, "authenticators/cookie_session (used by authors)") {
		t.Fatalf("message %q", c.Message)
	}
	inUse := map[string]string{}
	for _, u := range g.Status.InUse {
		inUse[u.Handler] = strings.Join(u.UsedBy, ",")
	}
	if !strings.Contains(inUse["authenticators/cookie_session"], "authors") || !strings.Contains(inUse["authorizers/remote_json"], "authors") {
		t.Fatalf("inUse %v", g.Status.InUse)
	}
	nothingWritten()

	// valid: a new immutable revision; the volume points at it, the pods that
	// have not been replaced keep the seed config
	updateGateway(t, func(s *authv1.GatewaySpec) { *s = platformGateway() })
	gwCond(t, authv1.GatewayConditionRolled, metav1.ConditionFalse, "RollingOut")
	first := waitMounted(t, seedConfigMap)
	rev := revisions(t)[first]
	if rev == nil || rev.Immutable == nil || !*rev.Immutable || !strings.HasPrefix(first, cfg.GatewayConfigPrefix+"-") ||
		!strings.Contains(rev.Data["config.yaml"], "check_session_url: http://kratos-public.auth/sessions/whoami") ||
		!strings.Contains(rev.Data["config.yaml"], "trust_forwarded_headers: true") {
		t.Fatalf("revision %s: %+v", first, rev)
	}
	if h := deployment(t).Spec.Template.Annotations[ConfigHashAnnotation]; first != cfg.GatewayConfigPrefix+"-"+h {
		t.Fatalf("config hash annotation %q for %s", h, first)
	}
	if v := deployment(t).Spec.Template.Spec.Volumes[1]; v.Name != "rules" || v.EmptyDir == nil {
		t.Fatalf("other volumes must not change: %+v", v)
	}
	oldPodUntouched(t)
	if g := getGateway(t); g.Status.ConfigMap != seedConfigMap {
		t.Fatalf("the seed is the first rollback target, got %q", g.Status.ConfigMap)
	}
	rollDeployment(t, first)
	g = gwCond(t, authv1.GatewayConditionReady, metav1.ConditionTrue, "Ready")
	if g.Status.ConfigMap != first || g.Status.ConfigHash != strings.TrimPrefix(first, cfg.GatewayConfigPrefix+"-") ||
		g.Status.Enabled == nil || strings.Join(g.Status.Enabled.Authenticators, ",") != "cookie_session,noop" {
		t.Fatalf("status %+v", g.Status)
	}

	// Sites are checked against the Gateway's handlers, not the flags (which enable bearer_token)
	s := newSite("tokens")
	s.Spec.Gates[1].Authenticators = []authv1.Handler{{Handler: "bearer_token"}}
	if err := k8s.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	cond(t, "tokens", authv1.ConditionValidated, metav1.ConditionFalse, validate.ReasonHandlerNotEnabled)

	// a rollout that never becomes Ready: pointed back to the last good revision
	fail := func(n int, good string) string {
		t.Helper()
		before := mounted(t)
		updateGateway(t, func(s *authv1.GatewaySpec) {
			s.Mutators["header"] = authv1.GatewayHandler{Enabled: true, Config: raw(fmt.Sprintf(`{"headers":{"X-Try":"%d"}}`, n))}
		})
		failed := waitMounted(t, before)
		g := gwCond(t, authv1.GatewayConditionApplied, metav1.ConditionFalse, "RolledBack")
		if g.Status.FailedHash != strings.TrimPrefix(failed, cfg.GatewayConfigPrefix+"-") {
			t.Fatalf("failedHash %q for %s", g.Status.FailedHash, failed)
		}
		eventually(t, "volume pointed back", func() error {
			if m := mounted(t); m != good {
				return fmt.Errorf("mounts %s", m)
			}
			return nil
		})
		rollDeployment(t, good)
		g = gwCond(t, authv1.GatewayConditionReady, metav1.ConditionFalse, "RolledBack")
		if g.Status.ConfigMap != good || revisions(t)[failed] == nil {
			t.Fatalf("status %+v", g.Status)
		}
		return failed
	}
	b := fail(1, first)

	// a new spec is tried again; enabling bearer_token lets the Site through once live
	updateGateway(t, func(s *authv1.GatewaySpec) {
		s.Mutators["header"] = platformGateway().Mutators["header"]
		s.Authenticators["bearer_token"] = authv1.GatewayHandler{Enabled: true, Config: raw(`{"check_session_url":"http://kratos-public.auth/sessions/whoami"}`)}
	})
	third := waitMounted(t, first)
	cond(t, "tokens", authv1.ConditionValidated, metav1.ConditionFalse, validate.ReasonHandlerNotEnabled) // not live yet
	rollDeployment(t, third)
	g = gwCond(t, authv1.GatewayConditionReady, metav1.ConditionTrue, "Ready")
	if g.Status.FailedHash != "" || g.Status.ConfigMap != third {
		t.Fatalf("status %+v", g.Status)
	}
	eventually(t, "site valid once bearer_token is live", func() error {
		c := meta.FindStatusCondition(getSite(t, "tokens").Status.Conditions, authv1.ConditionValidated)
		if c == nil || c.Status != metav1.ConditionTrue {
			return fmt.Errorf("%+v", c)
		}
		return nil
	})

	// pruning: three more failures keep the last good revision (beyond the newest
	// three) and never touch the seed; the next success deletes the oldest ones
	c, d, e := fail(2, third), fail(3, third), fail(4, third)
	have := revisions(t)
	for _, n := range []string{third, c, d, e} {
		if have[n] == nil {
			t.Fatalf("%s pruned too early: %v", n, keys(have))
		}
	}
	updateGateway(t, func(s *authv1.GatewaySpec) {
		s.Mutators["header"] = platformGateway().Mutators["header"]
		s.Errors.Handlers["json"] = authv1.GatewayHandler{Enabled: true, Config: raw(`{"verbose":true}`)}
	})
	last := waitMounted(t, third)
	rollDeployment(t, last)
	gwCond(t, authv1.GatewayConditionReady, metav1.ConditionTrue, "Ready")
	eventually(t, "oldest revisions pruned", func() error {
		have := revisions(t)
		want := []string{last, e, d}
		for _, n := range want {
			if have[n] == nil {
				return fmt.Errorf("%s missing: %v", n, keys(have))
			}
		}
		if len(have) != len(want) {
			return fmt.Errorf("have %v, want %v (first %s, b %s, c %s, third %s)", keys(have), want, first, b, c, third)
		}
		return nil
	})
	oldPodUntouched(t)
}

func keys(m map[string]*corev1.ConfigMap) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
