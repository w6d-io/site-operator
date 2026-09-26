package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"

	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
)

func TestSampleIsValid(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "config", "samples", "gateway.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var g authv1.Gateway
	if err := yaml.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	if p := Validate(&g.Spec); len(p) != 0 {
		t.Fatalf("%v", p)
	}
}
