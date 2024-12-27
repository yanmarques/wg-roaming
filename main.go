package main

import (
	"context"
	"flag"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

var (
	masterURL     string
	kubeconfig    string
	runAsManager  bool
	runAsOperator bool
)

var onlyOneSignalHandler = make(chan struct{})

// SetupSignalHandler registered for SIGTERM and SIGINT. A context is returned
// which is cancelled on one of these signals. If a second signal is caught,
// the program is terminated with exit code 1.
func setupSignalHandler() context.Context {
	// close(onlyOneSignalHandler) // panics when called twice
	//
	// c := make(chan os.Signal, 2)
	ctx, _ := context.WithCancel(context.Background())
	// signal.Notify(c)
	// go func() {
	// 	<-c
	// 	cancel()
	// 	<-c
	// 	os.Exit(1) // second signal. Exit directly.
	// }()

	return ctx
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	// set up signals so we handle the shutdown signal gracefully
	ctx := setupSignalHandler()
	logger := klog.FromContext(ctx)

	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	if err != nil {
		logger.Error(err, "Error building kubeconfig")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.Error(err, "Error building kubernetes clientset")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	// TODO: maybe a permission/http check here would be useful
	// nodes, err := kubeClient.CoreV1().Nodes().List(ctx, v1.ListOptions{})
	// logger.Info("found error", err)
	// logger.Info("found nodes", len(nodes.Items))

	if runAsManager {
		controller := NewController(ctx, kubeClient)

		if err = controller.Run(ctx, 2); err != nil {
			logger.Error(err, "Error running controller")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}

	} else if runAsOperator {
		operator := NewOperator(ctx, kubeClient)

		if err = operator.Run(ctx); err != nil {
			logger.Error(err, "Error running operator")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
	} else {
		peer := NewPeer(ctx, kubeClient)

		if err = peer.Run(ctx); err != nil {
			logger.Error(err, "Error running peer")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
	}
}

func init() {
	flag.BoolVar(&runAsManager, "runas-manager", false, "Whether to run as a manager")
	flag.BoolVar(&runAsOperator, "runas-operator", false, "Whether to run as a operator")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
}
