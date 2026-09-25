// Package scheme builds the runtime scheme shared by the operator and its tests.
package scheme

import (
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	okv1 "github.com/w6d-io/site-operator/api/oathkeeper/v1alpha1"
	authv1 "github.com/w6d-io/site-operator/api/v1alpha1"
)

// New returns a scheme with core types plus Site and Rule.
func New() *runtime.Scheme {
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, authv1.AddToScheme, okv1.AddToScheme} {
		if err := add(s); err != nil {
			panic(err)
		}
	}
	return s
}
