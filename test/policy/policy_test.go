// Package policy tests the shipped admission policies and RBAC manifests against
// a real kube-apiserver (envtest, v1.35): nothing here is re-implemented in Go.
package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
	"github.com/w6d-io/site-operator/internal/testenv"
)

const (
	jinbeUser    = "system:serviceaccount:auth:auth-jinbe"
	operatorUser = "system:serviceaccount:auth:site-operator"
	maesterUser  = "system:serviceaccount:auth:auth-oathkeeper-maester"
	intruderUser = "system:serviceaccount:auth:intruder"
	gcUser       = "system:serviceaccount:kube-system:generic-garbage-collector"
	shopURL      = "http://shop.shop.svc.cluster.local:8080"
)

var (
	ctx                                       = context.Background()
	restCfg                                   *rest.Config
	admin, jinbe, operator, maester, intruder client.Client
)

func TestMain(m *testing.M) {
	env := testenv.New()
	if env == nil {
		fmt.Println("envtest binaries not found; skipping policy tests")
		os.Exit(0)
	}
	var err error
	if restCfg, err = env.Start(); err != nil {
		panic(err)
	}
	admin = mustClient(restCfg)
	if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "auth"}}); err != nil {
		panic(err)
	}
	for _, dir := range []string{"rbac", "admission"} {
		if err := testenv.ApplyDir(ctx, admin, filepath.Join(testenv.Root(), "config", dir)); err != nil {
			panic(err)
		}
	}
	// grant maester (read/update) and an intruder (full) RBAC on Rules, so the
	// tests reach the admission policy rather than stopping at RBAC
	if err := grantRules(maesterUser, intruderUser, gcUser); err != nil {
		panic(err)
	}
	setZones("dev.example.com") // what the operator mirrors from Zone dev
	jinbe, operator = impersonate(jinbeUser), impersonate(operatorUser)
	maester, intruder = impersonate(maesterUser), impersonate(intruderUser)
	code := m.Run()
	_ = env.Stop()
	os.Exit(code)
}

func mustClient(c *rest.Config) client.Client {
	cl, err := client.New(c, client.Options{Scheme: testenv.Scheme()})
	if err != nil {
		panic(err)
	}
	return cl
}

func impersonate(user string) client.Client {
	c := rest.CopyConfig(restCfg)
	c.Impersonate = rest.ImpersonationConfig{
		UserName: user,
		Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:auth", "system:authenticated"},
	}
	return mustClient(c)
}

func grantRules(users ...string) error {
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "test-rules", Namespace: "auth"},
		Rules: []rbacv1.PolicyRule{{APIGroups: []string{"oathkeeper.ory.sh"}, Resources: []string{"rules"}, Verbs: []string{"*"}}}}
	if err := admin.Create(ctx, role); err != nil {
		return err
	}
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "test-rules", Namespace: "auth"},
		RoleRef: rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "test-rules"}}
	for _, u := range users {
		rb.Subjects = append(rb.Subjects, rbacv1.Subject{Kind: "User", Name: u})
	}
	return admin.Create(ctx, rb)
}

func setZones(domains string) { setZonesAndSecrets(domains, "") }

func setZonesAndSecrets(domains, secrets string) {
	cm := &corev1.ConfigMap{}
	if err := admin.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "site-operator-zones"}, cm); err != nil {
		panic(err)
	}
	cm.Data = map[string]string{"domains": domains, "secrets": secrets}
	if err := admin.Update(ctx, cm); err != nil {
		panic(err)
	}
}

func site(name, host string, up authv1.Upstream) *authv1.Site {
	return &authv1.Site{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth"},
		Spec: authv1.SiteSpec{
			Hosts:    []string{host},
			Upstream: up,
			Gates: []authv1.Gate{{
				Name:           "main",
				Match:          authv1.Match{URL: "<https?>://" + host + "/<.*>", Methods: []string{"GET"}},
				Authenticators: []authv1.Handler{{Handler: "noop"}},
				Authorizer:     authv1.Handler{Handler: "allow"},
			}},
		},
	}
}

func up(svc, ns string, port int32) authv1.Upstream {
	return authv1.Upstream{Service: svc, Namespace: ns, Port: port}
}

func ingress(name, host, backend string, ann, labels map[string]string) *networkingv1.Ingress {
	pt := networkingv1.PathTypeImplementationSpecific
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth", Annotations: ann, Labels: labels},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			Host: host,
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{Path: "/", PathType: &pt, Backend: networkingv1.IngressBackend{
					Service: &networkingv1.IngressServiceBackend{Name: backend, Port: networkingv1.ServiceBackendPort{Name: "http"}},
				}}},
			}},
		}}},
	}
}

var managed = map[string]string{"app.kubernetes.io/managed-by": "site-operator"}

func rule(name, upstream string) *okv1.Rule {
	t := true
	return &okv1.Rule{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "auth", Labels: map[string]string{"app.kubernetes.io/managed-by": "site-operator"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "auth.w6d.io/v1alpha1", Kind: "Site", Name: "shop", UID: "u1", Controller: &t}}},
		Spec: okv1.RuleSpec{
			Upstream: &okv1.Upstream{URL: upstream},
			Match:    &okv1.Match{URL: "<https?>://" + name + ".dev.example.com/<.*>", Methods: []string{"GET"}},
		},
	}
}

// denied waits until the policy is enforced and create is refused with want in the message.
func denied(t *testing.T, c client.Client, obj client.Object, want string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		err := c.Create(ctx, obj.DeepCopyObject().(client.Object))
		if err != nil && (apierrors.IsForbidden(err) || apierrors.IsInvalid(err)) && strings.Contains(err.Error(), want) {
			return
		}
		if err == nil {
			_ = admin.Delete(ctx, obj) // policy not active yet: undo and retry
		}
		if time.Now().After(deadline) {
			t.Fatalf("want denial containing %q, got %v", want, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func allowed(t *testing.T, c client.Client, obj client.Object) {
	t.Helper()
	if err := c.Create(ctx, obj); err != nil {
		t.Fatalf("want allowed, got %v", err)
	}
}

func TestSitePolicy(t *testing.T) {
	shop := up("shop", "shop", 8080)
	denied(t, jinbe, site("evil", "evil.example.com", shop), "under a Zone domain")
	denied(t, jinbe, site("nested", "a.b.dev.example.com", shop), "under a Zone domain")
	denied(t, jinbe, site("apex", "dev.example.com", shop), "under a Zone domain")
	denied(t, jinbe, site("login", "auth.dev.example.com", shop), "reserved hosts")
	denied(t, jinbe, site("admin", "admin.dev.example.com", up("auth-kratos-admin", "auth", 80)), "platform-internal")
	denied(t, jinbe, site("opa", "opa.dev.example.com", up("auth-opal-client", "auth", 7000)), "platform-internal")
	denied(t, jinbe, site("pol", "pol.dev.example.com", up("policy", "auth", 8181)), "platform-internal")
	denied(t, jinbe, site("cache", "cache.dev.example.com", up("jinbe-redis", "auth", 80)), "platform-internal")
	denied(t, jinbe, site("kube", "kube.dev.example.com", up("dns", "kube-system", 53)), "platform namespace")
	s := site("override", "override.dev.example.com", shop)
	o := up("postgres", "db", 5432)
	s.Spec.Gates[0].Upstream = &o
	denied(t, jinbe, s, "platform-internal")
	sys := site("signin", "auth.dev.example.com", up("auth-kratos-login-ui", "auth", 3000))
	sys.Spec.System = true
	denied(t, jinbe, sys, "system sites")

	allowed(t, jinbe, site("shop", "shop.dev.example.com", shop))
	allowed(t, admin, sys) // the chart (not jinbe) ships system sites
	got := &authv1.Site{}
	if err := jinbe.Get(ctx, client.ObjectKeyFromObject(sys), got); err != nil {
		t.Fatal(err)
	}
	if err := jinbe.Delete(ctx, got); err == nil || !strings.Contains(err.Error(), "system sites") {
		t.Fatalf("jinbe deleted a system site: %v", err)
	}
	got.Spec.System = false
	if err := jinbe.Update(ctx, got); err == nil || !strings.Contains(err.Error(), "system sites") {
		t.Fatalf("jinbe un-systemed a system site: %v", err)
	}
}

func TestNoZoneNoSite(t *testing.T) {
	setZones("")
	defer setZones("dev.example.com")
	denied(t, admin, site("nozone", "nozone.dev.example.com", up("shop", "shop", 8080)), "under a Zone domain")
}

func TestIngressPolicy(t *testing.T) {
	proxy := "auth-oathkeeper-proxy"
	denied(t, admin, ingress("steal", "steal.dev.example.com", "auth-kratos-admin", nil, nil), "backend must be auth-oathkeeper-proxy")
	denied(t, admin, ingress("opa", "opa.dev.example.com", "auth-opal-client", nil, nil), "backend must be auth-oathkeeper-proxy")
	denied(t, admin, ingress("pass", "pass.dev.example.com", proxy,
		map[string]string{"nginx.ingress.kubernetes.io/ssl-passthrough": "true"}, nil), "allow-list")
	denied(t, admin, ingress("authurl", "authurl.dev.example.com", proxy,
		map[string]string{"nginx.ingress.kubernetes.io/auth-url": "http://x"}, nil), "allow-list")
	denied(t, operator, ingress("rogue", "rogue.dev.example.com", proxy, nil, managed), "named site-<name> or zone-<name>")
	denied(t, operator, ingress("site-unlabelled", "u.dev.example.com", proxy, nil, nil), "named site-<name> or zone-<name>")
	denied(t, operator, ingress("zone-evil", "*.evil.com", proxy, nil, managed), "wildcard of a Zone domain")
	denied(t, operator, ingress("zone-deep", "*.x.dev.example.com", proxy, nil, managed), "wildcard of a Zone domain")
	denied(t, operator, ingress("site-far", "far.example.com", proxy, nil, managed), "one DNS label under a Zone domain")

	// the chart's own proxy Ingress keeps working
	allowed(t, admin, ingress("auth-oathkeeper-proxy", "auth.dev.example.com", proxy,
		map[string]string{"meta.helm.sh/release-name": "auth", "nginx.ingress.kubernetes.io/enable-cors": "true"}, nil))
	allowed(t, operator, ingress("zone-dev", "*.dev.example.com", proxy, map[string]string{"auth.w6d.io/spec-hash": "abcd1234"}, managed))
	allowed(t, operator, siteIngress("shop", "shop.dev.example.com", ""))
	helm := &networkingv1.Ingress{}
	if err := operator.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "auth-oathkeeper-proxy"}, helm); err != nil {
		t.Fatal(err)
	}
	if err := operator.Delete(ctx, helm); err == nil || !strings.Contains(err.Error(), "named site-<name>") {
		t.Fatalf("operator deleted the chart Ingress: %v", err)
	}
}

// siteIngress is a site-<site> Ingress controlled by Site site, with TLS secret (optional).
func siteIngress(site, host, secret string) *networkingv1.Ingress {
	ing := ingress("site-"+site, host, "auth-oathkeeper-proxy", map[string]string{"auth.w6d.io/spec-hash": "abcd1234"}, managed)
	t := true
	ing.OwnerReferences = []metav1.OwnerReference{{APIVersion: "auth.w6d.io/v1alpha1", Kind: "Site", Name: site, UID: "u1", Controller: &t}}
	if secret != "" {
		ing.Spec.TLS = []networkingv1.IngressTLS{{Hosts: []string{host}, SecretName: secret}}
	}
	return ing
}

// Per-site Ingresses (vanity, or a per-site Zone): exact host under a Zone,
// controlled by the Site they are named after, own or Zone TLS Secret only.
func TestSiteIngressPolicy(t *testing.T) {
	setZonesAndSecrets("dev.example.com", "dev-wildcard")
	t.Cleanup(func() { setZones("dev.example.com") })
	denied(t, operator, siteIngress("wild", "*.dev.example.com", ""), "one DNS label under a Zone domain")
	notOwned := siteIngress("orphan", "orphan.dev.example.com", "")
	notOwned.OwnerReferences[0].Name = "other"
	denied(t, operator, notOwned, "named site-<site> and controlled by that Site")
	denied(t, operator, siteIngress("thief", "thief.dev.example.com", "auth-kratos-tls"), "own TLS Secret or its Zone's")
	allowed(t, operator, siteIngress("own", "own.dev.example.com", "site-own-tls"))
	allowed(t, operator, siteIngress("zoned", "zoned.dev.example.com", "dev-wildcard"))
}

func TestRulePolicy(t *testing.T) {
	denied(t, admin, rule("admin", "http://auth-kratos-admin.auth.svc.cluster.local:80"), "platform-internal")
	denied(t, admin, rule("opa", "http://opa.auth.svc.cluster.local:8181"), "platform-internal")
	denied(t, admin, rule("pg", "http://auth-postgresql.auth.svc.cluster.local:5432"), "platform-internal")
	denied(t, admin, rule("free", "http://example.com/"), "platform-internal or non-cluster")
	cm := "kube-root-ca.crt"
	r := rule("cm", shopURL)
	r.Spec.ConfigMapName = &cm
	denied(t, admin, r, "maester ConfigMap")
	denied(t, intruder, rule("intruder", shopURL), "may not write maester Rules")
	bare := rule("bare", shopURL)
	bare.Labels, bare.OwnerReferences = nil, nil
	denied(t, operator, bare, "owner reference to their Site")
	allowed(t, operator, rule("shop-main-abcd1234", shopURL))

	// maester may add its finalizer and status, but never change the spec
	got := &okv1.Rule{}
	if err := maester.Get(ctx, client.ObjectKey{Namespace: "auth", Name: "shop-main-abcd1234"}, got); err != nil {
		t.Fatal(err)
	}
	valid := true
	got.Finalizers = []string{"finalizer.oathkeeper.ory.sh"}
	got.Status.Validation = &okv1.Validation{Valid: &valid}
	if err := maester.Update(ctx, got); err != nil {
		t.Fatalf("maester status update refused: %v", err)
	}
	got.Spec.Upstream.URL = "http://elsewhere.elsewhere.svc.cluster.local:80"
	if err := maester.Update(ctx, got); err == nil || !strings.Contains(err.Error(), "may not write") {
		t.Fatalf("maester changed a rule spec: %v", err)
	}
	if err := intruder.Delete(ctx, got); err == nil || !strings.Contains(err.Error(), "may not write") {
		t.Fatalf("intruder deleted a rule: %v", err)
	}
	if err := impersonate(gcUser).Delete(ctx, got); err != nil {
		t.Fatalf("garbage collector delete refused: %v", err)
	}
}

// TestChartIngressesPass applies every Ingress the auth chart renders for the
// three environments: a Helm upgrade must never be rejected by the policies.
func TestChartIngressesPass(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "chart-ingresses.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	denied(t, admin, ingress("db", "db.dev.example.com", "auth-oathkeeper-proxy",
		map[string]string{"nginx.ingress.kubernetes.io/default-backend": "auth-kratos-admin"}, nil), "default-backend may only be error-page")
	n := 0
	for _, doc := range strings.Split(string(raw), "\n---") {
		ing := &networkingv1.Ingress{}
		if err := yaml.Unmarshal([]byte(doc), ing); err != nil {
			t.Fatal(err)
		}
		if ing.Name == "" {
			continue
		}
		ing.Name += "-" + strings.ReplaceAll(ing.Labels["test.source"], "_", "-")
		if err := admin.Create(ctx, ing); err != nil {
			t.Fatalf("chart Ingress from %s rejected: %v", ing.Labels["test.source"], err)
		}
		n++
	}
	if n != 3 {
		t.Fatalf("want the 3 chart Ingresses (one per env), got %d", n)
	}
}
