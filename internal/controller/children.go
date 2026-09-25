package controller

import (
	"context"
	"errors"
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/w6d-io/site-operator/internal/render"
)

// errConflict marks a child name already used by an object the owner does not control.
var errConflict = errors.New("name taken by an object this owner does not control")

// children writes owned Ingresses and Certificates; shared by the Site and Zone controllers.
type children struct {
	client.Client
	Recorder record.EventRecorder
}

func (c children) ingress(ctx context.Context, owner client.Object, want *networkingv1.Ingress) (*networkingv1.Ingress, error) {
	got := &networkingv1.Ingress{}
	err := c.Get(ctx, client.ObjectKeyFromObject(want), got)
	if apierrors.IsNotFound(err) {
		if err := c.Create(ctx, want); err != nil {
			return nil, err
		}
		c.Recorder.Eventf(owner, "Normal", "IngressCreated", "created Ingress %s", want.Name)
		return want, nil
	}
	if err != nil {
		return nil, err
	}
	if !metav1.IsControlledBy(got, owner) {
		return nil, errConflict
	}
	if equality.Semantic.DeepEqual(got.Spec, want.Spec) && maps(got.Labels, want.Labels) && maps(got.Annotations, want.Annotations) {
		return got, nil
	}
	got.Spec, got.Labels, got.Annotations = want.Spec, want.Labels, want.Annotations
	if err := c.Update(ctx, got); err != nil {
		return nil, err
	}
	c.Recorder.Eventf(owner, "Normal", "IngressUpdated", "updated Ingress %s", want.Name)
	return got, nil
}

func (c children) certificate(ctx context.Context, owner client.Object, want *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	got := &unstructured.Unstructured{}
	got.SetGroupVersionKind(render.CertificateGVK)
	err := c.Get(ctx, client.ObjectKeyFromObject(want), got)
	if apierrors.IsNotFound(err) {
		if err := c.Create(ctx, want); err != nil {
			return nil, err
		}
		c.Recorder.Eventf(owner, "Normal", "CertificateCreated", "created Certificate %s", want.GetName())
		return want, nil
	}
	if err != nil {
		return nil, err
	}
	if !metav1.IsControlledBy(got, owner) {
		return nil, errConflict
	}
	if got.GetAnnotations()[render.SpecHashAnnotation] == want.GetAnnotations()[render.SpecHashAnnotation] {
		return got, nil
	}
	got.Object["spec"] = want.Object["spec"]
	got.SetLabels(want.GetLabels())
	got.SetAnnotations(want.GetAnnotations())
	if err := c.Update(ctx, got); err != nil {
		return nil, err
	}
	return got, nil
}

// deleteOwned deletes key if owner controls it; a missing object or CRD is fine.
func (c children) deleteOwned(ctx context.Context, owner client.Object, obj client.Object, key client.ObjectKey) error {
	if err := c.Get(ctx, key, obj); err != nil {
		if meta.IsNoMatchError(err) {
			return nil
		}
		return client.IgnoreNotFound(err)
	}
	if !metav1.IsControlledBy(obj, owner) {
		return nil
	}
	if err := c.Delete(ctx, obj); client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("delete %s: %w", key.Name, err)
	}
	return nil
}

func (c children) deleteIngress(ctx context.Context, owner client.Object, key client.ObjectKey) error {
	return c.deleteOwned(ctx, owner, &networkingv1.Ingress{}, key)
}

func (c children) deleteCertificate(ctx context.Context, owner client.Object, key client.ObjectKey) error {
	cert := &unstructured.Unstructured{}
	cert.SetGroupVersionKind(render.CertificateGVK)
	return c.deleteOwned(ctx, owner, cert, key)
}

func maps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// certReady reads a cert-manager Certificate's Ready condition.
func certReady(cert *unstructured.Unstructured) (ok bool, reason, msg string) {
	conds, _, _ := unstructured.NestedSlice(cert.Object, "status", "conditions")
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["type"] != "Ready" {
			continue
		}
		reason, _ = m["reason"].(string)
		msg, _ = m["message"].(string)
		if reason == "" {
			reason = "Pending"
		}
		return m["status"] == "True", reason, msg
	}
	return false, "Pending", "cert-manager has not reported yet"
}

// lbAddress is the first load-balancer address of an admitted Ingress ("" if none).
func lbAddress(ing *networkingv1.Ingress) string {
	if len(ing.Status.LoadBalancer.Ingress) == 0 {
		return ""
	}
	lb := ing.Status.LoadBalancer.Ingress[0]
	if lb.Hostname != "" {
		return lb.Hostname
	}
	return lb.IP
}
