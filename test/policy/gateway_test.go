package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/testenv"
)

// eventuallyErr retries f until it returns an error containing want (policies
// take a moment to be enforced after creation), or nil when want is "".
func eventuallyErr(t *testing.T, want string, f func() error) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		err := f()
		if want == "" && err == nil || want != "" && err != nil && strings.Contains(err.Error(), want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("want %q, got %v", want, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func versioned(name string, immutable bool) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth"}, Immutable: &immutable,
		Data: map[string]string{"config.yaml": "log: {level: info}\n"}}
}

func TestVersionedConfigOnlyOperator(t *testing.T) {
	// the intruder gets full ConfigMap RBAC so the request reaches the policy
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "test-cm", Namespace: "auth"},
		Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"*"}}}}
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "test-cm", Namespace: "auth"},
		RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "test-cm"},
		Subjects: []rbacv1.Subject{{Kind: "User", Name: intruderUser}}}
	for _, o := range []client.Object{role, rb} {
		if err := admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	denied(t, intruder, versioned("auth-oathkeeper-config-0123abcd", true), "may not CREATE the versioned Oathkeeper config")
	denied(t, operator, versioned("auth-oathkeeper-config-0123abcd", false), "may not CREATE the versioned Oathkeeper config")
	denied(t, operator, versioned("kratos-config", true), "only versioned Oathkeeper config ConfigMaps")
	denied(t, operator, versioned("auth-oathkeeper-config-0123abcde", true), "only versioned Oathkeeper config ConfigMaps")
	allowed(t, operator, versioned("auth-oathkeeper-config-0123abcd", true))

	cm := versioned("auth-oathkeeper-config-0123abcd", true)
	eventuallyErr(t, "may not DELETE the versioned Oathkeeper config", func() error { return intruder.Delete(ctx, cm.DeepCopy()) })
	other := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "auth"}}
	allowed(t, intruder, other) // other ConfigMaps are not this policy's business
	eventuallyErr(t, "only versioned Oathkeeper config ConfigMaps", func() error { return operator.Delete(ctx, other.DeepCopy()) })
	eventuallyErr(t, "", func() error { return operator.Delete(ctx, cm.DeepCopy()) })
	if err := jinbe.Create(ctx, versioned("auth-oathkeeper-config-0123abce", true)); !apierrors.IsForbidden(err) {
		t.Fatalf("jinbe created a config: %v", err)
	}
}

func oathkeeperDeployment() *appsv1.Deployment {
	two := int32(2)
	labels := map[string]string{"app.kubernetes.io/name": "oathkeeper"}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "auth-oathkeeper", Namespace: "auth"},
		Spec: appsv1.DeploymentSpec{Replicas: &two, Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels, Annotations: map[string]string{"checksum/config": "abc"}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "oathkeeper", Image: "oryd/oathkeeper:v25.4.0"}},
					Volumes: []corev1.Volume{
						{Name: "oathkeeper-config-volume", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "auth-oathkeeper-config"}}}},
						{Name: "oathkeeper-rules-volume", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
						{Name: "secrets", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "auth-oathkeeper"}}},
					}}}},
	}
}

func TestOperatorOnlyRollsOathkeeper(t *testing.T) {
	dep := oathkeeperDeployment()
	allowed(t, admin, dep)
	patch := func(p string) error {
		return operator.Patch(ctx, dep.DeepCopy(), client.RawPatch(types.StrategicMergePatchType, []byte(p)))
	}
	// what the operator does: annotation + config volume to a versioned config, and back to the seed
	eventuallyErr(t, "", func() error {
		return patch(`{"spec":{"template":{"metadata":{"annotations":{"auth.w6d.io/gateway-config-hash":"0123abcd"}},` +
			`"spec":{"volumes":[{"name":"oathkeeper-config-volume","configMap":{"name":"auth-oathkeeper-config-0123abcd"}}]}}}}`)
	})
	eventuallyErr(t, "", func() error {
		return patch(`{"spec":{"template":{"metadata":{"annotations":{"auth.w6d.io/gateway-config-hash":null}},` +
			`"spec":{"volumes":[{"name":"oathkeeper-config-volume","configMap":{"name":"auth-oathkeeper-config"}}]}}}}`)
	})

	for name, tc := range map[string]struct{ patch, want string }{
		"image":              {`{"spec":{"template":{"spec":{"containers":[{"name":"oathkeeper","image":"evil:latest"}]}}}}`, "may not change the Oathkeeper pod spec"},
		"hostNetwork":        {`{"spec":{"template":{"spec":{"hostNetwork":true}}}}`, "may not change the Oathkeeper pod spec"},
		"serviceAccount":     {`{"spec":{"template":{"spec":{"serviceAccountName":"auth-kratos"}}}}`, "may not change the Oathkeeper pod spec"},
		"replicas":           {`{"spec":{"replicas":0}}`, "may only change the pod-template annotation"},
		"other annotation":   {`{"spec":{"template":{"metadata":{"annotations":{"checksum/config":"zzz"}}}}}`, "may only change the pod-template annotation"},
		"label":              {`{"metadata":{"labels":{"x":"y"}}}`, "may only change the pod-template annotation"},
		"config to any cm":   {`{"spec":{"template":{"spec":{"volumes":[{"name":"oathkeeper-config-volume","configMap":{"name":"kratos-config"}}]}}}}`, "only point the config volume"},
		"config items":       {`{"spec":{"template":{"spec":{"volumes":[{"name":"oathkeeper-config-volume","configMap":{"name":"auth-oathkeeper-config-0123abcd","items":[{"key":"a","path":"config.yaml"}]}}]}}}}`, "only point the config volume"},
		"other volume":       {`{"spec":{"template":{"spec":{"volumes":[{"name":"secrets","secret":{"secretName":"auth-kratos"}}]}}}}`, "only point the config volume"},
		"rules volume to cm": {`{"spec":{"template":{"spec":{"volumes":[{"name":"oathkeeper-rules-volume","emptyDir":null,"configMap":{"name":"auth-oathkeeper-config-0123abcd"}}]}}}}`, "only point the config volume"},
		"add volume":         {`{"spec":{"template":{"spec":{"volumes":[{"name":"x","hostPath":{"path":"/"}}]}}}}`, "only point the config volume"},
	} {
		t.Run(name, func(t *testing.T) { eventuallyErr(t, tc.want, func() error { return patch(tc.patch) }) })
	}
}

// TestRolloutPolicyCoversPodSpec: the rollout policy compares every PodSpec field
// but volumes; a field added to the API without a comparison would be writable.
func TestRolloutPolicyCoversPodSpec(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(testenv.Root(), "config", "admission", "gateway_policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// newer than the 1.35 API server (the typed CEL check would refuse them)
	notServed := map[string]bool{"schedulingGroup": true, "evictionResponders": true}
	pt := reflect.TypeOf(corev1.PodSpec{})
	for i := range pt.NumField() {
		f := strings.Split(pt.Field(i).Tag.Get("json"), ",")[0]
		if f == "volumes" || notServed[f] {
			continue
		}
		if !strings.Contains(string(b), "variables.ps.?"+f+" == variables.ops.?"+f) {
			t.Errorf("PodSpec.%s is not compared by site-operator-gateway-rollout", f)
		}
	}
	dt := reflect.TypeOf(appsv1.DeploymentSpec{})
	for i := range dt.NumField() {
		f := strings.Split(dt.Field(i).Tag.Get("json"), ",")[0]
		if f != "template" && !strings.Contains(string(b), "object.spec."+f) && !strings.Contains(string(b), "object.spec.?"+f) {
			t.Errorf("DeploymentSpec.%s is not compared", f)
		}
	}
}

func TestGatewayWriters(t *testing.T) {
	gw := &authv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "auth"},
		Spec: authv1.GatewaySpec{Authenticators: map[string]authv1.GatewayHandler{"noop": {Enabled: true}}}}
	allowed(t, jinbe, gw)
	if err := jinbe.Create(ctx, &authv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: "auth"}}); !apierrors.IsInvalid(err) ||
		!strings.Contains(err.Error(), "singleton") {
		t.Fatalf("a second Gateway: %v", err)
	}
	if err := jinbe.Delete(ctx, gw); !apierrors.IsForbidden(err) {
		t.Fatalf("jinbe may not delete the Gateway: %v", err)
	}
	err := jinbe.Patch(ctx, gw, client.RawPatch(types.MergePatchType, []byte(`{"spec":{"mutators":{"teleport":{"enabled":true}}}}`)))
	if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), "unknown mutator") {
		t.Fatalf("unknown handler: %v", err)
	}
}
