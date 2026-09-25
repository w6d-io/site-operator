// Package testenv starts an envtest API server with the operator CRDs.
package testenv

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	"github.com/w6d-io/site-operator/internal/scheme"
)

// K8sVersion is the API server version the tests run against (the clusters run 1.35).
const K8sVersion = "1.35.0"

// Root is the repository root.
func Root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// Scheme holds core types plus Site and Rule.
func Scheme() *k8sruntime.Scheme { return scheme.New() }

// New returns an envtest environment with every CRD the operator touches, or
// nil when no envtest binaries are available.
func New() *envtest.Environment {
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		bin := "setup-envtest"
		if gp, err := exec.Command("go", "env", "GOPATH").Output(); err == nil {
			if p := filepath.Join(strings.TrimSpace(string(gp)), "bin", "setup-envtest"); fileExists(p) {
				bin = p
			}
		}
		out, err := exec.Command(bin, "use", "-i", K8sVersion, "-p", "path").Output()
		if err != nil {
			return nil
		}
		assets = strings.TrimSpace(string(out))
	}
	root := Root()
	return &envtest.Environment{
		BinaryAssetsDirectory: assets,
		CRDDirectoryPaths: []string{
			filepath.Join(root, "config", "crd", "bases"),
			filepath.Join(root, "config", "crd", "external"),
			filepath.Join(root, "test", "testdata"),
		},
		ErrorIfCRDPathMissing: true,
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ApplyDir creates every document of every *.yaml file in dir except kustomization.yaml.
func ApplyDir(ctx context.Context, c client.Client, dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return err
	}
	var names []string
	for _, f := range files {
		if filepath.Base(f) != "kustomization.yaml" {
			names = append(names, filepath.Base(f))
		}
	}
	return ApplyFiles(ctx, c, dir, names...)
}

// ApplyFiles creates every document of the named files in dir.
func ApplyFiles(ctx context.Context, c client.Client, dir string, names ...string) error {
	for _, n := range names {
		f := filepath.Join(dir, n)
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		for _, doc := range strings.Split(string(raw), "\n---") {
			u := &unstructured.Unstructured{}
			if err := yaml.Unmarshal([]byte(doc), &u.Object); err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			if len(u.Object) == 0 {
				continue
			}
			if err := c.Create(ctx, u); err != nil {
				return fmt.Errorf("%s %s: %w", f, u.GetName(), err)
			}
		}
	}
	return nil
}
