package policy

import (
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// can asks the RBAC authorizer (SubjectAccessReview), like `kubectl auth can-i --as`.
func can(t *testing.T, user, verb, group, resource, sub string) bool {
	t.Helper()
	sar := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
		User:   user,
		Groups: []string{"system:serviceaccounts", "system:serviceaccounts:auth", "system:authenticated"},
		ResourceAttributes: &authzv1.ResourceAttributes{
			Namespace: "auth", Verb: verb, Group: group, Resource: resource, Subresource: sub,
		},
	}}
	if err := admin.Create(ctx, sar); err != nil {
		t.Fatal(err)
	}
	return sar.Status.Allowed
}

func TestRBAC(t *testing.T) {
	type check struct {
		verb, group, resource, sub string
		want                       bool
	}
	jinbeChecks := []check{
		{"create", "auth.w6d.io", "sites", "", true},
		{"delete", "auth.w6d.io", "sites", "", true},
		{"get", "auth.w6d.io", "sites", "status", true},
		{"update", "auth.w6d.io", "sites", "status", false},
		{"create", "networking.k8s.io", "ingresses", "", false},
		{"update", "networking.k8s.io", "ingresses", "", false},
		{"create", "oathkeeper.ory.sh", "rules", "", false},
		{"create", "cert-manager.io", "certificates", "", false},
		{"create", "", "services", "", false},
		{"get", "", "secrets", "", false},
		{"create", "", "configmaps", "", false},
		{"create", "auth.w6d.io", "gateways", "", true},
		{"update", "auth.w6d.io", "gateways", "", true},
		{"delete", "auth.w6d.io", "gateways", "", false},
		{"update", "auth.w6d.io", "gateways", "status", false},
		{"patch", "apps", "deployments", "", false},
	}
	for _, c := range jinbeChecks {
		if got := can(t, jinbeUser, c.verb, c.group, c.resource, c.sub); got != c.want {
			t.Errorf("jinbe %s %s/%s %s: got %v want %v", c.verb, c.group, c.resource, c.sub, got, c.want)
		}
	}
	operatorChecks := []check{
		{"create", "oathkeeper.ory.sh", "rules", "", true},
		{"create", "networking.k8s.io", "ingresses", "", true},
		{"create", "cert-manager.io", "certificates", "", true},
		{"update", "auth.w6d.io", "sites", "status", true},
		{"update", "auth.w6d.io", "sites", "", false},
		{"get", "", "secrets", "", false},
		{"create", "", "configmaps", "", true}, // versioned Gateway configs only (admission)
		{"delete", "", "configmaps", "", true}, // idem
		{"list", "", "configmaps", "", false},
		{"get", "", "configmaps", "", false},
		{"create", "", "services", "", false},
		// RulesLoaded reads each gateway pod's /rules: list + get, nothing else
		{"list", "", "pods", "", true},
		{"get", "", "pods", "", true},
		{"watch", "", "pods", "", false},
		{"delete", "", "pods", "", false},
		{"create", "", "pods", "exec", false},
		{"get", "", "pods", "log", false},
		{"update", "auth.w6d.io", "gateways", "", false},
		{"update", "auth.w6d.io", "gateways", "status", true},
		{"list", "apps", "deployments", "", false},
		{"create", "apps", "deployments", "", false},
	}
	for _, c := range operatorChecks {
		if got := can(t, operatorUser, c.verb, c.group, c.resource, c.sub); got != c.want {
			t.Errorf("operator %s %s/%s %s: got %v want %v", c.verb, c.group, c.resource, c.sub, got, c.want)
		}
	}
	// and for real, through the API server as jinbe
	err := jinbe.Create(ctx, ingress("site-x", "x.dev.example.com", "auth-oathkeeper-proxy", nil, nil))
	if !apierrors.IsForbidden(err) {
		t.Fatalf("jinbe created an Ingress: %v", err)
	}
	err = jinbe.Create(ctx, rule("x", shopURL))
	if !apierrors.IsForbidden(err) {
		t.Fatalf("jinbe created a Rule: %v", err)
	}
}

// resourceNames RBAC: the operator may update its zones mirror and the rendered
// Oathkeeper config (Gateway), no other ConfigMap.
func TestOperatorConfigMapScope(t *testing.T) {
	check := func(name string, want bool) {
		sar := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
			User: operatorUser, Groups: []string{"system:serviceaccounts", "system:authenticated"},
			ResourceAttributes: &authzv1.ResourceAttributes{Namespace: "auth", Verb: "update", Resource: "configmaps", Name: name},
		}}
		if err := admin.Create(ctx, sar); err != nil {
			t.Fatal(err)
		}
		if sar.Status.Allowed != want {
			t.Errorf("operator update configmap %s: got %v want %v", name, sar.Status.Allowed, want)
		}
	}
	check("site-operator-zones", true)
	check("auth-oathkeeper-config", false)      // the chart's seed: never updated, versioned configs are created
	check("auth-oathkeeper-config-base", false) // the chart's base config: read only
	check("site-operator-policy", false)
}

// Ingresses: read cluster-wide (HostTaken check), write only in the gateway namespace.
func TestOperatorIngressScope(t *testing.T) {
	for _, c := range []struct {
		ns, verb string
		want     bool
	}{
		{"legacy", "list", true}, {"legacy", "watch", true}, {"legacy", "get", true}, {"", "list", true},
		{"legacy", "create", false}, {"legacy", "update", false}, {"legacy", "delete", false},
		{"auth", "create", true},
	} {
		sar := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
			User: operatorUser, Groups: []string{"system:serviceaccounts", "system:authenticated"},
			ResourceAttributes: &authzv1.ResourceAttributes{Namespace: c.ns, Verb: c.verb, Group: "networking.k8s.io", Resource: "ingresses"},
		}}
		if err := admin.Create(ctx, sar); err != nil {
			t.Fatal(err)
		}
		if sar.Status.Allowed != c.want {
			t.Errorf("operator %s ingresses in %q: got %v want %v", c.verb, c.ns, sar.Status.Allowed, c.want)
		}
	}
}
