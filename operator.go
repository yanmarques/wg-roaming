package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/time/rate"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	kubeerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

type Operator struct {
	// Wireguard keys
	key *wgtypes.Key

	nodeName string

	// kubeclientset is a standard kubernetes clientset
	kubeclientset kubernetes.Interface

	// processes configmap with certificate events
	cmWorkqueue   workqueue.TypedRateLimitingInterface[*corev1.ConfigMap]
	nodeWorkqueue workqueue.TypedRateLimitingInterface[NodeEvent]

	sharedFactory kubeinformers.SharedInformerFactory

	cmInformer   cache.SharedIndexInformer
	nodeInformer cache.SharedIndexInformer

	nodeList map[string]*corev1.Node
}

// publish an updated version of the certificate
func PublishCert(ctx context.Context, kubeClient kubernetes.Interface, key *wgtypes.Key, nodeName string) error {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
		Data: map[string]string{
			"pubKey": key.PublicKey().String(),
		},
	}

	_, err := kubeClient.CoreV1().ConfigMaps(controllerNamespace).Get(ctx, nodeName, v1.GetOptions{})
	if kubeerrors.IsNotFound(err) {
		_, err := kubeClient.CoreV1().ConfigMaps(controllerNamespace).Create(ctx, cm, metav1.CreateOptions{})
		return err
	}

	if err != nil {
		return err
	}

	_, err = kubeClient.CoreV1().ConfigMaps(controllerNamespace).Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

// func (event NodeEvent) Equals(other NodeEvent) bool {
// 	return event.node.Name == other.node.Name
// }

func NewOperator(
	ctx context.Context,
	kubeClient kubernetes.Interface,
) *Operator {
	logger := klog.FromContext(ctx)

	cmRatelimiter := workqueue.NewTypedMaxOfRateLimiter(
		workqueue.NewTypedItemExponentialFailureRateLimiter[*corev1.ConfigMap](5*time.Millisecond, 1000*time.Second),
		&workqueue.TypedBucketRateLimiter[*corev1.ConfigMap]{Limiter: rate.NewLimiter(rate.Limit(50), 300)},
	)

	nodeRatelimiter := workqueue.NewTypedMaxOfRateLimiter(
		workqueue.NewTypedItemExponentialFailureRateLimiter[NodeEvent](5*time.Millisecond, 1000*time.Second),
		&workqueue.TypedBucketRateLimiter[NodeEvent]{Limiter: rate.NewLimiter(rate.Limit(50), 300)},
	)

	sharedFactory := kubeinformers.NewSharedInformerFactory(kubeClient, time.Second*30)
	key, err := grabWireguardKey()
	if err != nil {
		logger.Error(err, "unable to grab a valid wireguard key")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	nodeName, ok := os.LookupEnv("NODE_NAME")
	if !ok {
		logger.Error(err, "missing 'NODE_NAME' environment variable with the current node's name")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	operator := &Operator{
		kubeclientset: kubeClient,
		key:           key,
		nodeName:      nodeName,
		cmWorkqueue:   workqueue.NewTypedRateLimitingQueue(cmRatelimiter),
		nodeWorkqueue: workqueue.NewTypedRateLimitingQueue(nodeRatelimiter),
		sharedFactory: sharedFactory,
		cmInformer:    sharedFactory.Core().V1().ConfigMaps().Informer(),
		nodeInformer:  sharedFactory.Core().V1().Nodes().Informer(),
	}

	// Set up event handlers for the configmap informer
	operator.cmInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cm := obj.(*corev1.ConfigMap)
			if IsMainConfig(cm) {
				operator.cmWorkqueue.Add(cm)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			cm := newObj.(*corev1.ConfigMap)
			if IsMainConfig(cm) {
				operator.cmWorkqueue.Add(cm)
			}
		},
	})

	// // Set up event handlers for the node informer
	// operator.nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
	// 	AddFunc: func(obj interface{}) {
	// 		event := NodeEvent{node: obj.(*corev1.Node), event: nodeEventAdd}
	// 		operator.nodeWorkqueue.Add(event)
	// 	},
	// 	UpdateFunc: func(oldObj, newObj interface{}) {
	// 		event := NodeEvent{node: newObj.(*corev1.Node), event: nodeEventAdd}
	// 		operator.nodeWorkqueue.Add(event)
	// 	},
	// 	DeleteFunc: func(obj interface{}) {
	// 		event := NodeEvent{node: obj.(*corev1.Node), event: nodeEventAdd}
	// 		operator.nodeWorkqueue.Add(event)
	// 	},
	// })

	return operator
}

func (o *Operator) Run(ctx context.Context) error {
	defer utilruntime.HandleCrash()
	defer o.cmWorkqueue.ShutDown()

	logger := klog.FromContext(ctx)

	err := PublishCert(ctx, o.kubeclientset, o.key, o.nodeName)
	if err != nil {
		logger.Error(err, "unable to publish certificate")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	// Wait for the caches to be synced before starting workers
	logger.Info("Waiting for informer caches to sync")

	o.sharedFactory.Start(ctx.Done())

	ok := cache.WaitForNamedCacheSync(controllerAgentName, ctx.Done(), o.cmInformer.HasSynced, o.nodeInformer.HasSynced)
	if !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	// Start mainconfig worker
	go wait.UntilWithContext(ctx, o.runMainConfigWorker, time.Second)
	go wait.UntilWithContext(ctx, o.runNodeWorker, time.Second)

	logger.Info("Started workers")
	<-ctx.Done()
	logger.Info("Shutting down workers")

	return nil
}

func (o *Operator) runMainConfigWorker(ctx context.Context) {
	for o.processNextConfigMaptem(ctx) {
	}
}

func (o *Operator) runNodeWorker(ctx context.Context) {
	for o.processNextNodeItem(ctx) {
	}
}

func (o *Operator) processNextConfigMaptem(ctx context.Context) bool {
	cm, shutdown := o.cmWorkqueue.Get()
	logger := klog.FromContext(ctx)

	if shutdown {
		return false
	}

	defer o.cmWorkqueue.Done(cm)

	err := o.onMainConfigChanged(ctx, cm)
	if err == nil {
		o.cmWorkqueue.Forget(cm)
		logger.Info("Successfully synced", "configMap", cm.Name)
		return true
	}

	utilruntime.HandleErrorWithContext(ctx, err, "Error syncing; requeuing for later retry", "configMap", cm.Name)
	o.cmWorkqueue.AddRateLimited(cm)

	return true
}

func (o *Operator) processNextNodeItem(ctx context.Context) bool {
	event, shutdown := o.nodeWorkqueue.Get()
	logger := klog.FromContext(ctx)

	if shutdown {
		return false
	}

	defer o.nodeWorkqueue.Done(event)

	err := o.onNodesChanged(ctx, event)
	if err == nil {
		o.nodeWorkqueue.Forget(event)
		logger.Info("Successfully synced", "event", event.node.Name)
		return true
	}

	utilruntime.HandleErrorWithContext(ctx, err, "Error syncing; requeuing for later retry", "node", event.node.Name)
	o.nodeWorkqueue.AddRateLimited(event)

	return true
}

func (o *Operator) onNodesChanged(ctx context.Context, event NodeEvent) error {
	logger := klog.FromContext(ctx)

	if event.event == nodeEventDelete {
		logger.Info("node deleted", "node", event.node.Name)
		delete(o.nodeList, event.node.Name)
	} else {
		logger.Info("node add/updated", "node", event.node.Name)
		o.nodeList[event.node.Name] = event.node
	}

	return nil
}

func (o *Operator) onMainConfigChanged(ctx context.Context, cm *corev1.ConfigMap) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "configMap", cm.Name)

	mainConfig := MainConfig{}
	err := json.Unmarshal([]byte(cm.Data["mainConfig"]), &mainConfig)
	if err != nil {
		logger.Error(err, "unable to unmarshal main config, giving up...")
		return err
	}

	listenPort := 51820

	cfg := wgtypes.Config{
		PrivateKey:   o.key,
		ListenPort:   &listenPort,
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{},
	}

	routePeers := []net.IP{}
	for _, peer := range mainConfig.Peers {
		peerIP := net.ParseIP(peer.IfaceIP)

		routePeers = append(routePeers, peerIP)

		pubKey, err := wgtypes.ParseKey(peer.PubKey)
		if err != nil {
			logger.Error(err, "unable to parse peer public key", "pubKey", peer.PubKey)
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}

		vpnSubnet := net.IPNet{IP: peerIP, Mask: net.IPv4Mask(255, 255, 0, 0)}
		peerCfg := wgtypes.PeerConfig{
			PublicKey:         pubKey,
			Remove:            false,
			ReplaceAllowedIPs: false,
			AllowedIPs:        []net.IPNet{vpnSubnet},
		}
		cfg.Peers = append(cfg.Peers, peerCfg)
	}

	client, err := wgctrl.New()
	if err != nil {
		return err
	}

	defer client.Close()

	la := netlink.NewLinkAttrs()
	la.Name = "wg0"
	la.MTU = 1500
	link := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}

	ourIP := net.ParseIP(mainConfig.IfaceIP)
	if ourIP == nil {
		logger.Error(err, "unable to parse vpn iface ip", "ip", ourIP, "config", cm.Name)
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	if err := ensureLink(ctx, link, &net.IPNet{IP: ourIP, Mask: net.IPv4Mask(255, 255, 255, 255)}); err != nil {
		logger.Error(err, "unable to configure network link", "ip", ourIP)
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	_, vpnSubnet, err := net.ParseCIDR(vpnCIDR)
	if err != nil {
		logger.Error(err, "bug: invalid vpn cidr", "cidr", vpnCIDR)
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	if err := upAndRoutes(ctx, link, []net.IPNet{*vpnSubnet}); err != nil {
		logger.Error(err, "unable to configure network routes")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	err = client.ConfigureDevice("wg0", cfg)
	if err != nil {
		logger.Error(err, "unable to configure wireguard device")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	logger.Info("configured device")

	return nil
}
