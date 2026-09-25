package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/render"
)

var ctx = context.Background()

func raw(s string) *runtime.RawExtension { return &runtime.RawExtension{Raw: []byte(s)} }

func newSite(name string) *authv1.Site {
	host := name + ".dev.example.com"
	return &authv1.Site{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth"},
		Spec: authv1.SiteSpec{
			Hosts:    []string{host},
			Upstream: authv1.Upstream{Service: name, Namespace: name, Port: 8080},
			Gates: []authv1.Gate{
				{
					Name:           "public",
					Match:          authv1.Match{URL: "<https?>://" + host + "/<(health|docs)(/.*)?>", Methods: []string{"GET"}},
					Authenticators: []authv1.Handler{{Handler: "noop"}},
					Authorizer:     authv1.Handler{Handler: "allow"},
				},
				{
					Name:           "browser",
					Match:          authv1.Match{URL: "<https?>://" + host + "/<(?!(health|docs)(/.*)?$).*>", Methods: []string{"GET", "POST"}},
					Authenticators: []authv1.Handler{{Handler: "cookie_session"}},
					Authorizer: authv1.Handler{Handler: "remote_json", Config: raw(`{"remote":"http://opa-authz-proxy.auth:8080/v1/data/rbac/allow",` +
						`"payload":"{\"input\":{\"sub\":\"{{ print .Subject }}\",\"app\":\"` + name + `\"}}"}`)},
					Mutators: []authv1.Handler{{Handler: "header", Config: raw(`{"headers":{"X-User":"{{ print .Subject }}"}}`)}},
				},
			},
		},
	}
}

func getSite(t *testing.T, name string) *authv1.Site {
	t.Helper()
	s := &authv1.Site{}
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: name}, s); err != nil {
		t.Fatal(err)
	}
	return s
}

func rulesOf(t *testing.T, site string) []okv1.Rule {
	t.Helper()
	var l okv1.RuleList
	if err := k8s.List(ctx, &l, client.InNamespace("auth"), client.MatchingLabels{render.SiteLabel: site}); err != nil {
		t.Fatal(err)
	}
	return l.Items
}

// cond waits until the Site has observed its generation and condition typ has status/reason.
func cond(t *testing.T, name, typ string, status metav1.ConditionStatus, reason string) *authv1.Site {
	t.Helper()
	var s *authv1.Site
	eventually(t, fmt.Sprintf("%s %s=%s/%s", name, typ, status, reason), func() error {
		s = getSite(t, name)
		c := meta.FindStatusCondition(s.Status.Conditions, typ)
		if s.Status.ObservedGeneration != s.Generation || c == nil || c.ObservedGeneration != s.Generation {
			return fmt.Errorf("generation %d not observed yet: %+v", s.Generation, s.Status)
		}
		if c.Status != status || (reason != "" && c.Reason != reason) {
			return fmt.Errorf("got %s/%s: %s", c.Status, c.Reason, c.Message)
		}
		return nil
	})
	return s
}

func updateSite(t *testing.T, name string, f func(*authv1.Site)) {
	t.Helper()
	eventually(t, "update site", func() error {
		s := getSite(t, name)
		f(s)
		return k8s.Update(ctx, s)
	})
}

func ingressOf(name string) (*networkingv1.Ingress, error) {
	ing := &networkingv1.Ingress{}
	return ing, k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: name}, ing)
}

func ownedBy(t *testing.T, obj metav1.Object, owner metav1.Object) {
	t.Helper()
	if !metav1.IsControlledBy(obj, owner) {
		t.Fatalf("%s is not controlled by %s: %+v", obj.GetName(), owner.GetName(), obj.GetOwnerReferences())
	}
}

// ackRules simulates maester acknowledging every Rule of the site (the maester
// CRD has no status subresource: maester updates the whole object).
func ackRules(t *testing.T, site string) {
	t.Helper()
	valid := true
	for _, r := range rulesOf(t, site) {
		r.Status.Validation = &okv1.Validation{Valid: &valid}
		if err := k8s.Update(ctx, &r); err != nil {
			t.Fatal(err)
		}
	}
}

func admitIngress(t *testing.T, name string) {
	t.Helper()
	ing, err := ingressOf(name)
	if err != nil {
		t.Fatal(err)
	}
	ing.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{{Hostname: "a884b7ca.elb.amazonaws.com"}}
	if err := k8s.Status().Update(ctx, ing); err != nil {
		t.Fatal(err)
	}
}

func assertNothingWritten(t *testing.T, name string) {
	t.Helper()
	consistently(t, "nothing written for "+name, 2*time.Second, func() error {
		if n := len(rulesOf(t, name)); n != 0 {
			return fmt.Errorf("%d rules written", n)
		}
		if _, err := ingressOf("site-" + name); !apierrors.IsNotFound(err) {
			return fmt.Errorf("ingress written: %v", err)
		}
		return nil
	})
}

func names(rs []okv1.Rule) map[string]bool {
	m := map[string]bool{}
	for _, r := range rs {
		m[r.Name] = true
	}
	return m
}

func twoRules(t *testing.T, site string) map[string]bool {
	t.Helper()
	var got map[string]bool
	eventually(t, site+" has 2 rules", func() error {
		if got = names(rulesOf(t, site)); len(got) != 2 {
			return fmt.Errorf("have %v", got)
		}
		return nil
	})
	return got
}
