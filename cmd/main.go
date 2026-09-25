// Command site-operator reconciles auth.w6d.io Sites into oathkeeper-maester
// Rules, an Ingress and, when needed, a cert-manager Certificate.
package main

import (
	"flag"
	"os"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/w6d-io/site-operator/internal/config"
	"github.com/w6d-io/site-operator/internal/controller"
	"github.com/w6d-io/site-operator/internal/scheme"
	"github.com/w6d-io/site-operator/internal/validate"
)

func main() {
	var metricsAddr, probeAddr string
	var leaderElect bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "metrics endpoint address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "health probe address")
	flag.BoolVar(&leaderElect, "leader-elect", true, "enable leader election")
	raw := config.Register(flag.CommandLine)
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("setup")

	cfg, err := raw.Load()
	if err != nil {
		log.Error(err, "invalid configuration")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme.New(),
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          leaderElect,
		LeaderElectionID:        "site-operator.auth.w6d.io",
		LeaderElectionNamespace: cfg.GatewayNamespace,
		// the operator only ever reads and writes the gateway namespace (namespaced Role)
		Cache: cache.Options{DefaultNamespaces: map[string]cache.Config{cfg.GatewayNamespace: {}}},
	})
	if err != nil {
		log.Error(err, "unable to create manager")
		os.Exit(1)
	}
	r := &controller.SiteReconciler{
		Client:    mgr.GetClient(),
		Config:    cfg,
		Validator: validate.NewGatekit(cfg.GatekitURL),
		Recorder:  mgr.GetEventRecorderFor("site-operator"),
	}
	if err := r.SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to set up site controller")
		os.Exit(1)
	}
	z := &controller.ZoneReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Config:    cfg,
		Recorder:  mgr.GetEventRecorderFor("site-operator"),
	}
	if err := z.SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to set up zone controller")
		os.Exit(1)
	}
	_ = mgr.AddHealthzCheck("healthz", healthz.Ping)
	_ = mgr.AddReadyzCheck("readyz", healthz.Ping)
	log.Info("starting", "namespace", cfg.GatewayNamespace, "gatekit", cfg.GatekitURL)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "manager exited")
		os.Exit(1)
	}
}
