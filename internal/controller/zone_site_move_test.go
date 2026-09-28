package controller

import (
	"fmt"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/render"
)

// moveHost rewrites a Site's host the way jinbe renders an address change:
// spec.hosts and every gate's match URL, nothing else.
func moveHost(t *testing.T, name, to string) {
	t.Helper()
	updateSite(t, name, func(s *authv1.Site) {
		from := s.Spec.Hosts[0]
		s.Spec.Hosts = []string{to}
		for i := range s.Spec.Gates {
			s.Spec.Gates[i].Match.URL = strings.ReplaceAll(s.Spec.Gates[i].Match.URL, from, to)
		}
	})
}

// replayMove watches the Site's Rules while its host moves and checks what
// maester would write at every step: the same Rules (no retire, no delete, no
// new name), each matching exactly one of the two hosts, until all match `to`.
func replayMove(t *testing.T, name, from, to string, before map[string]bool, move func()) {
	t.Helper()
	var list okv1.RuleList
	if err := k8s.List(ctx, &list, client.InNamespace("auth"), client.MatchingLabels{render.SiteLabel: name}); err != nil {
		t.Fatal(err)
	}
	w, err := watchC.Watch(ctx, &okv1.RuleList{}, client.InNamespace("auth"),
		client.MatchingLabels{render.SiteLabel: name}, &client.ListOptions{Raw: &metav1.ListOptions{ResourceVersion: list.ResourceVersion}})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	move()

	host := map[string]string{}
	for _, r := range list.Items {
		host[r.Name] = from
	}
	deadline := time.After(15 * time.Second)
	for moved := 0; moved < len(before); {
		select {
		case ev := <-w.ResultChan():
			r, ok := ev.Object.(*okv1.Rule)
			if !ok {
				t.Fatalf("unexpected watch event %v", ev)
			}
			if ev.Type == watch.Deleted || render.Retired(r) || !before[r.Name] {
				t.Fatalf("a host move must update Rules in place; got %s %s (retired=%v)", ev.Type, r.Name, render.Retired(r))
			}
			url := r.Spec.Match.URL
			onFrom, onTo := strings.Contains(url, "://"+from+"/"), strings.Contains(url, "://"+to+"/")
			if onFrom == onTo {
				t.Fatalf("rule %s matches %s: want exactly one of %s, %s", r.Name, url, from, to)
			}
			if onTo && host[r.Name] == from {
				moved++
			}
			if onFrom && host[r.Name] == to {
				t.Fatalf("rule %s moved back to %s", r.Name, from)
			}
			host[r.Name] = map[bool]string{true: to, false: from}[onTo]
		case <-deadline:
			t.Fatalf("host move not observed; rules at %v", host)
		}
	}
}

// TestHostChangeMovesSiteInPlace: a Site changing host — label and zone —
// keeps its Rule names (the name hashes the templates only), so each Rule's
// match moves from the old host to the new one in one write: never a Rule on
// both hosts, never a retire/delete gap. The Site's host Ingresses follow the
// zone: none under a wildcard Zone, one under a per-site Zone, the old host's
// released when the label changes, and released again when it leaves the Zone.
func TestHostChangeMovesSiteInPlace(t *testing.T) {
	zone := &authv1.Zone{ObjectMeta: metav1.ObjectMeta{Name: "moves"},
		Spec: authv1.ZoneSpec{Domain: "moves.example.com", Ingress: authv1.ZoneIngressPerSite, TLS: authv1.ZoneTLS{Mode: authv1.ZoneTLSDefault}}}
	if err := k8s.Create(ctx, zone); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	// the zone is mirrored into the admission ConfigMap other tests read: leave nothing behind
	t.Cleanup(func() { _ = k8s.Delete(ctx, zone) })
	zoneCond(t, "moves", authv1.ConditionReady, metav1.ConditionTrue, "Ready")

	const (
		dev    = "mover.dev.example.com"
		first  = "mover.moves.example.com"
		second = "relabelled.moves.example.com"
	)
	if err := k8s.Create(ctx, newSite("mover")); err != nil {
		t.Fatal(err)
	}
	cond(t, "mover", authv1.ConditionValidated, metav1.ConditionTrue, "Valid")
	before := twoRules(t, "mover")
	ackRules(t, "mover")
	cond(t, "mover", authv1.ConditionIngressReady, metav1.ConditionTrue, "Zone")

	// wildcard zone → per-site zone: rules move in place, the new host gets its Ingress
	replayMove(t, "mover", dev, first, before, func() { moveHost(t, "mover", first) })
	cond(t, "mover", authv1.ConditionValidated, metav1.ConditionTrue, "Valid")
	eventually(t, "host Ingress for "+first, func() error {
		ing, err := ingressOf(render.HostIngressName(first))
		if err != nil {
			return err
		}
		if len(ing.Spec.Rules) != 1 || ing.Spec.Rules[0].Host != first || !ownedBySite(ing, "mover") {
			return fmt.Errorf("host Ingress %+v owners %+v", ing.Spec.Rules, ing.OwnerReferences)
		}
		return nil
	})

	// relabel inside the per-site zone: new host Ingress, the old one released and deleted
	replayMove(t, "mover", first, second, before, func() { moveHost(t, "mover", second) })
	eventually(t, "host Ingress for "+second, func() error {
		ing, err := ingressOf(render.HostIngressName(second))
		if err != nil {
			return err
		}
		if !ownedBySite(ing, "mover") {
			return fmt.Errorf("owners %+v", ing.OwnerReferences)
		}
		return nil
	})
	gone(t, render.HostIngressName(first))

	// back under the wildcard zone: no Ingress of its own left
	replayMove(t, "mover", second, dev, before, func() { moveHost(t, "mover", dev) })
	gone(t, render.HostIngressName(second))
	cond(t, "mover", authv1.ConditionIngressReady, metav1.ConditionTrue, "Zone")
	for _, r := range rulesOf(t, "mover") {
		if !before[r.Name] || !strings.Contains(r.Spec.Match.URL, "://"+dev+"/") {
			t.Fatalf("rule %s at %s after the moves; want the same rules on %s", r.Name, r.Spec.Match.URL, dev)
		}
		if r.Status.Validation == nil || r.Status.Validation.Valid == nil || !*r.Status.Validation.Valid {
			t.Fatalf("maester's acknowledgement lost on %s", r.Name)
		}
	}
}
