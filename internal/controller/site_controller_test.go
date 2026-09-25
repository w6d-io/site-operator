package controller

import (
	"fmt"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/render"
	"github.com/w6d-io/site-operator/internal/validate"
)

func TestZoneSiteRendersRulesOnly(t *testing.T) {
	if err := k8s.Create(ctx, newSite("payroll")); err != nil {
		t.Fatal(err)
	}
	site := cond(t, "payroll", authv1.ConditionValidated, metav1.ConditionTrue, "Valid")
	cond(t, "payroll", authv1.ConditionRulesSynced, metav1.ConditionFalse, "WaitingForMaester")
	cond(t, "payroll", authv1.ConditionRulesLoaded, metav1.ConditionUnknown, "NotMeasured")
	cond(t, "payroll", authv1.ConditionIngressReady, metav1.ConditionTrue, "Zone")
	cond(t, "payroll", authv1.ConditionCertificateReady, metav1.ConditionTrue, "Zone")

	rules := rulesOf(t, "payroll")
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}
	for i := range rules {
		ownedBy(t, &rules[i], site)
		if u := rules[i].Spec.Upstream.URL; u != "http://payroll.payroll.svc.cluster.local:8080" {
			t.Fatalf("upstream %s", u)
		}
	}
	if _, err := ingressOf("site-payroll"); !apierrors.IsNotFound(err) {
		t.Fatalf("a zone host needs no per-site Ingress: %v", err)
	}

	ackRules(t, "payroll")
	site = cond(t, "payroll", authv1.ConditionReady, metav1.ConditionTrue, "Ready")
	if len(site.Status.Children) != 2 {
		t.Fatalf("want 2 children (rules), got %+v", site.Status.Children)
	}
}

// TestTemplateChangeSwapsRuleSafely watches the Rules the way maester does and
// checks that no observer ever sees two live Rules for one gate: the old Rule is
// retired (unroutable match) before its replacement exists, then deleted.
func TestTemplateChangeSwapsRuleSafely(t *testing.T) {
	if err := k8s.Create(ctx, newSite("billing")); err != nil {
		t.Fatal(err)
	}
	cond(t, "billing", authv1.ConditionValidated, metav1.ConditionTrue, "Valid")
	before := twoRules(t, "billing")

	var list okv1.RuleList
	if err := k8s.List(ctx, &list, client.InNamespace("auth"), client.MatchingLabels{render.SiteLabel: "billing"}); err != nil {
		t.Fatal(err)
	}
	w, err := watchC.Watch(ctx, &okv1.RuleList{}, client.InNamespace("auth"),
		client.MatchingLabels{render.SiteLabel: "billing"}, &client.ListOptions{Raw: &metav1.ListOptions{ResourceVersion: list.ResourceVersion}})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	updateSite(t, "billing", func(s *authv1.Site) {
		s.Spec.Gates[1].Mutators[0].Config = raw(`{"headers":{"X-User":"{{ print .Extra.email }}"}}`)
	})

	// replay the watch: state[name] = live (not retired) rule of which gate
	live := map[string]string{}
	for n := range before {
		for _, r := range list.Items {
			if r.Name == n {
				live[n] = r.Labels[render.GateLabel]
			}
		}
	}
	deadline := time.After(15 * time.Second)
	for done := false; !done; {
		select {
		case ev := <-w.ResultChan():
			r, ok := ev.Object.(*okv1.Rule)
			if !ok {
				t.Fatalf("unexpected watch event %v", ev)
			}
			if ev.Type == watch.Deleted || render.Retired(r) {
				delete(live, r.Name)
			} else {
				live[r.Name] = r.Labels[render.GateLabel]
			}
			perGate := map[string]int{}
			for _, g := range live {
				if perGate[g]++; perGate[g] > 1 {
					t.Fatalf("two live rules for gate %s at once: %v", g, live)
				}
			}
			if ev.Type == watch.Deleted && !before[r.Name] {
				t.Fatalf("new rule %s deleted", r.Name)
			}
			done = ev.Type == watch.Deleted && before[r.Name]
		case <-deadline:
			t.Fatalf("no swap observed; live=%v", live)
		}
	}

	eventually(t, "one rule per gate after reconcile", func() error {
		rs := rulesOf(t, "billing")
		kept, added := 0, 0
		for _, r := range rs {
			if render.Retired(&r) {
				return fmt.Errorf("retired rule %s still present", r.Name)
			}
			if before[r.Name] {
				kept++
			} else {
				added++
			}
		}
		if len(rs) != 2 || kept != 1 || added != 1 {
			return fmt.Errorf("before %v after %v", before, names(rs))
		}
		return nil
	})
	cond(t, "billing", authv1.ConditionValidated, metav1.ConditionTrue, "Valid")
	for _, c := range getSite(t, "billing").Status.Children {
		if !names(rulesOf(t, "billing"))[c.Name] {
			t.Fatalf("status lists a deleted rule %s", c.Name)
		}
	}
}

func TestPausedSwapsInDenyRules(t *testing.T) {
	s := newSite("shop")
	s.Spec.Exposure.Mode = authv1.ExposureVanity
	if err := k8s.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	cond(t, "shop", authv1.ConditionValidated, metav1.ConditionTrue, "Valid")
	before := twoRules(t, "shop")

	updateSite(t, "shop", func(s *authv1.Site) { s.Spec.Paused = true })
	site := cond(t, "shop", authv1.ConditionReady, metav1.ConditionFalse, "Paused")
	var paused okv1.Rule
	eventually(t, "gate rules replaced by one paused deny rule", func() error {
		rs := rulesOf(t, "shop")
		if len(rs) != 1 || rs[0].Labels[render.GateLabel] != "paused-0" {
			return fmt.Errorf("rules %v", names(rs))
		}
		paused = rs[0]
		return nil
	})
	if paused.Spec.Authorizer.Handler != "deny" || paused.Spec.Match.URL != "<https?>://shop.dev.example.com/<.*>" ||
		len(paused.Spec.Match.Methods) != 7 || paused.Spec.Errors[len(paused.Spec.Errors)-1].Handler != "json" {
		t.Fatalf("bad paused rule %+v", paused.Spec)
	}
	if _, err := ingressOf("site-shop"); err != nil {
		t.Fatalf("the vanity Ingress must stay so visitors reach the paused rule: %v", err)
	}
	if meta.FindStatusCondition(site.Status.Conditions, authv1.ConditionValidated) == nil {
		t.Fatalf("status must be kept: %+v", site.Status)
	}

	updateSite(t, "shop", func(s *authv1.Site) { s.Spec.Paused = false })
	cond(t, "shop", authv1.ConditionValidated, metav1.ConditionTrue, "Valid")
	eventually(t, "gate rules back", func() error {
		if got := names(rulesOf(t, "shop")); fmt.Sprint(got) != fmt.Sprint(before) {
			return fmt.Errorf("rules %v, want %v", got, before)
		}
		return nil
	})
}

func TestPauseWorksWithGatekitDown(t *testing.T) {
	s := newSite("down-pause")
	s.Spec.Paused = true
	if err := k8s.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	cond(t, "down-pause", authv1.ConditionValidated, metav1.ConditionTrue, "Paused")
	eventually(t, "paused rule written", func() error {
		if n := len(rulesOf(t, "down-pause")); n != 1 {
			return fmt.Errorf("%d rules", n)
		}
		return nil
	})
}

func TestRefusalsWriteNothing(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*authv1.Site)
		reason string
		status metav1.ConditionStatus
	}{
		{"broken", func(s *authv1.Site) {
			s.Spec.Gates[0].Match.URL = "<https?>://broken.dev.example.com/<((health>"
		}, validate.ReasonPatternInvalid, metav1.ConditionFalse},
		{"sneaky", func(s *authv1.Site) {
			s.Spec.Upstream = authv1.Upstream{Service: "auth-kratos-admin", Namespace: "auth", Port: 80}
		}, validate.ReasonUpstreamNotAllowed, metav1.ConditionFalse},
		{"foreign", func(s *authv1.Site) { s.Spec.Hosts = []string{"foreign.example.com"} }, validate.ReasonHostNotInZone, metav1.ConditionFalse},
		{"unpinned", func(s *authv1.Site) {
			s.Spec.Gates[1].Authorizer.Config = raw(`{"payload":"{\"input\":{}}"}`)
		}, validate.ReasonAppNotPinned, metav1.ConditionFalse},
		{"jwt", func(s *authv1.Site) {
			s.Spec.Gates[1].Authenticators = []authv1.Handler{{Handler: "jwt"}}
		}, validate.ReasonHandlerNotEnabled, metav1.ConditionFalse},
		{"down-app", func(*authv1.Site) {}, validate.ReasonValidatorUnavailable, metav1.ConditionUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newSite(tc.name)
			tc.mutate(s)
			if err := k8s.Create(ctx, s); err != nil {
				t.Fatal(err)
			}
			cond(t, tc.name, authv1.ConditionValidated, tc.status, tc.reason)
			cond(t, tc.name, authv1.ConditionReady, metav1.ConditionFalse, tc.reason)
			assertNothingWritten(t, tc.name)
		})
	}
}

func TestRefusedUpdateKeepsServingRules(t *testing.T) {
	if err := k8s.Create(ctx, newSite("steady")); err != nil {
		t.Fatal(err)
	}
	cond(t, "steady", authv1.ConditionValidated, metav1.ConditionTrue, "Valid")
	before := twoRules(t, "steady")
	updateSite(t, "steady", func(s *authv1.Site) {
		s.Spec.Gates[1].Match.URL = "<https?>://steady.dev.example.com/<((.*>"
	})
	cond(t, "steady", authv1.ConditionValidated, metav1.ConditionFalse, validate.ReasonPatternInvalid)
	consistently(t, "previous rules untouched", time.Second, func() error {
		for _, r := range rulesOf(t, "steady") {
			if !before[r.Name] || render.Retired(&r) {
				return fmt.Errorf("rules changed: %v -> %s", before, r.Name)
			}
		}
		return nil
	})
}

func TestDriftOnRuleIsRestored(t *testing.T) {
	if err := k8s.Create(ctx, newSite("drift")); err != nil {
		t.Fatal(err)
	}
	cond(t, "drift", authv1.ConditionValidated, metav1.ConditionTrue, "Valid")
	twoRules(t, "drift")
	var name string
	eventually(t, "edit a rule", func() error {
		rs := rulesOf(t, "drift")
		name = rs[0].Name
		rs[0].Spec.Upstream.URL = "http://elsewhere.elsewhere.svc.cluster.local:80"
		return k8s.Update(ctx, &rs[0])
	})
	eventually(t, "rule restored", func() error {
		r := &okv1.Rule{}
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: name}, r); err != nil {
			return err
		}
		if r.Spec.Upstream.URL != "http://drift.drift.svc.cluster.local:8080" {
			return fmt.Errorf("upstream still %s", r.Spec.Upstream.URL)
		}
		return nil
	})
}

func TestVanityIngressAndPerSiteCertificate(t *testing.T) {
	s := newSite("secure")
	s.Spec.Exposure = authv1.Exposure{Mode: authv1.ExposureVanity, TLS: authv1.TLSPerSite}
	if err := k8s.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	site := cond(t, "secure", authv1.ConditionCertificateReady, metav1.ConditionFalse, "Pending")
	cond(t, "secure", authv1.ConditionIngressReady, metav1.ConditionFalse, "WaitingForAddress")
	ing, err := ingressOf("site-secure")
	if err != nil {
		t.Fatal(err)
	}
	ownedBy(t, ing, site)
	if b := ing.Spec.Rules[0].HTTP.Paths[0].Backend.Service; b.Name != "auth-oathkeeper-proxy" || b.Port.Name != "http" {
		t.Fatalf("ingress backend not pinned: %+v", b)
	}
	if ing.Annotations["nginx.ingress.kubernetes.io/proxy-read-timeout"] != "300" || ing.Spec.TLS[0].SecretName != "site-secure-tls" {
		t.Fatalf("bad vanity ingress: %+v", ing)
	}
	admitIngress(t, "site-secure")
	cond(t, "secure", authv1.ConditionIngressReady, metav1.ConditionTrue, "Admitted")

	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(render.CertificateGVK)
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "site-secure"}, cert); err != nil {
		t.Fatal(err)
	}
	ownedBy(t, cert, site)
	_ = unstructured.SetNestedSlice(cert.Object, []any{map[string]any{"type": "Ready", "status": "True", "reason": "Ready", "message": "issued"}}, "status", "conditions")
	if err := k8s.Status().Update(ctx, cert); err != nil {
		t.Fatal(err)
	}
	cond(t, "secure", authv1.ConditionCertificateReady, metav1.ConditionTrue, "Issued")

	updateSite(t, "secure", func(s *authv1.Site) { s.Spec.Exposure = authv1.Exposure{} })
	cond(t, "secure", authv1.ConditionCertificateReady, metav1.ConditionTrue, "Zone")
	eventually(t, "vanity children removed", func() error {
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "site-secure"}, cert); !apierrors.IsNotFound(err) {
			return fmt.Errorf("certificate still there: %v", err)
		}
		if _, err := ingressOf("site-secure"); !apierrors.IsNotFound(err) {
			return fmt.Errorf("ingress still there: %v", err)
		}
		return nil
	})
}
