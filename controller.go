package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"golang.org/x/time/rate"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const controllerAgentName = "wg-roaming"
const controllerMainconfigName = "wg-roaming-mainconfig"
const controllerNamespace = "kube-system-wg"
const controllerUri = "wg-roaming.k8s.io"

const nodeEventAdd = "add"
const nodeEventUpdate = "update"
const nodeEventDelete = "delete"

const vpnCIDR = "172.16.0.0/16"

type NodeEvent struct {
	// Kubernetes node involved in the event
	node *corev1.Node

	// Type of event
	event string
}

type NodeInfo struct {
	node        *corev1.Node
	certificate string
	ifaceIP     net.IP
}

type PeerCfg struct {
	IfaceIP string
	PubKey  string
}

type MainConfig struct {
	Endpoint string
	PubKey   string
	NodeName string
	IfaceIP  string
	Peers    []PeerCfg
}

type Controller struct {
	clusterPodCIDR *net.IPNet

	// kubeclientset is a standard kubernetes clientset
	kubeclientset kubernetes.Interface

	// processes node events
	nodeWorkqueue workqueue.TypedRateLimitingInterface[NodeEvent]
	cmWorkqueue   workqueue.TypedRateLimitingInterface[*corev1.ConfigMap]

	sharedFactory kubeinformers.SharedInformerFactory

	nodeInformer cache.SharedIndexInformer
	cmInformer   cache.SharedIndexInformer

	peers   map[string]*NodeInfo
	vpnNode *NodeInfo
}

func (event NodeEvent) Equals(other NodeEvent) bool {
	return event.node.Name == other.node.Name
}

func IsMainConfig(cm *corev1.ConfigMap) bool {
	return cm.Name == controllerMainconfigName
}

func (n *NodeInfo) isComplete() bool {
	return n.node != nil && n.certificate != ""
}

// NewController returns a new sample controller
func NewController(
	ctx context.Context,
	kubeClient kubernetes.Interface,
) *Controller {
	logger := klog.FromContext(ctx)

	logger.V(4).Info("Creating event broadcaster")

	nodeRatelimiter := workqueue.NewTypedMaxOfRateLimiter(
		workqueue.NewTypedItemExponentialFailureRateLimiter[NodeEvent](5*time.Millisecond, 1000*time.Second),
		&workqueue.TypedBucketRateLimiter[NodeEvent]{Limiter: rate.NewLimiter(rate.Limit(50), 300)},
	)

	cmRatelimiter := workqueue.NewTypedMaxOfRateLimiter(
		workqueue.NewTypedItemExponentialFailureRateLimiter[*corev1.ConfigMap](5*time.Millisecond, 1000*time.Second),
		&workqueue.TypedBucketRateLimiter[*corev1.ConfigMap]{Limiter: rate.NewLimiter(rate.Limit(50), 300)},
	)

	sharedFactory := kubeinformers.NewSharedInformerFactory(kubeClient, time.Second*30)

	controller := &Controller{
		kubeclientset: kubeClient,
		nodeWorkqueue: workqueue.NewTypedRateLimitingQueue(nodeRatelimiter),
		cmWorkqueue:   workqueue.NewTypedRateLimitingQueue(cmRatelimiter),
		sharedFactory: sharedFactory,
		nodeInformer:  sharedFactory.Core().V1().Nodes().Informer(),
		cmInformer:    sharedFactory.Core().V1().ConfigMaps().Informer(),
		peers:         map[string]*NodeInfo{},
	}

	// Set up event handlers for the node informer
	controller.nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			event := NodeEvent{node: obj.(*corev1.Node), event: nodeEventAdd}
			controller.nodeWorkqueue.Add(event)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			event := NodeEvent{node: newObj.(*corev1.Node), event: nodeEventAdd}
			controller.nodeWorkqueue.Add(event)
		},
		DeleteFunc: func(obj interface{}) {
			event := NodeEvent{node: obj.(*corev1.Node), event: nodeEventAdd}
			controller.nodeWorkqueue.Add(event)
		},
	})

	controller.cmInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cm := obj.(*corev1.ConfigMap)
			if cm.Namespace == "kube-system-wg" {
				controller.cmWorkqueue.Add(cm)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			cm := newObj.(*corev1.ConfigMap)
			if cm.Namespace == "kube-system-wg" {
				controller.cmWorkqueue.Add(cm)
			}
		},
	})

	logger.Info("Setting up event handlers")
	return controller
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *Controller) Run(ctx context.Context, workers int) error {
	// defer utilruntime.HandleCrash()
	defer c.nodeWorkqueue.ShutDown()
	defer c.cmWorkqueue.ShutDown()
	logger := klog.FromContext(ctx)

	// TODO: how to automatically get this?
	_, podCIDR, err := net.ParseCIDR("10.244.0.1/16")
	if err != nil {
		return err
	}

	// Set cluster PodCIDR before running the worker
	c.clusterPodCIDR = podCIDR

	// Wait for the caches to be synced before starting workers
	logger.Info("Waiting for informer caches to sync")

	c.sharedFactory.Start(ctx.Done())

	ok := cache.WaitForCacheSync(ctx.Done(), c.nodeInformer.HasSynced, c.cmInformer.HasSynced)
	if !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	logger.Info("Starting workers", "count", workers)

	// Start workers
	go wait.UntilWithContext(ctx, c.runNodeDiscovery, time.Second)
	go wait.UntilWithContext(ctx, c.runCertDiscovery, time.Second)

	logger.Info("Started workers")
	<-ctx.Done()
	logger.Info("Shutting down workers")

	return nil
}

// runWorker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runNodeDiscovery(ctx context.Context) {
	for c.processNextNode(ctx) {
	}
}

func (c *Controller) runCertDiscovery(ctx context.Context) {
	for c.processNextCertificate(ctx) {
	}
}

// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *Controller) processNextNode(ctx context.Context) bool {
	event, shutdown := c.nodeWorkqueue.Get()
	logger := klog.FromContext(ctx)

	if shutdown {
		return false
	}

	defer c.nodeWorkqueue.Done(event)

	// Run the syncHandler, passing it the structured reference to the object to be synced.
	err := c.onNodesChanged(ctx, event)
	if err == nil {
		// If no error occurs then we Forget this item so it does not
		// get queued again until another change happens.
		c.nodeWorkqueue.Forget(event)
		logger.Info("Successfully synced", "nodeEvent", event.node.Name)
		return false
	}

	utilruntime.HandleErrorWithContext(ctx, err, "Error syncing; requeuing for later retry", "node", event)
	c.nodeWorkqueue.AddRateLimited(event)
	return false
}

func (c *Controller) processNextCertificate(ctx context.Context) bool {
	logger := klog.LoggerWithValues(klog.FromContext(ctx))
	cert, shutdown := c.cmWorkqueue.Get()

	if shutdown {
		return false
	}

	defer c.cmWorkqueue.Done(cert)

	err := c.onCertChanged(ctx, cert)
	if err == nil {
		c.cmWorkqueue.Forget(cert)
		logger.Info("Successfully synced", "cert", cert.Name)
		return false
	}

	utilruntime.HandleErrorWithContext(ctx, err, "Error syncing; requeuing for later retry", "cert", cert)
	c.cmWorkqueue.AddRateLimited(cert)

	return false
}

func (c *Controller) updateMainConfig(ctx context.Context) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx))

	if c.vpnNode == nil {
		logger.Error(nil, "bug: unable to update main config without a vpn node")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	mainConfig := MainConfig{
		NodeName: c.vpnNode.node.Name,
		PubKey:   c.vpnNode.certificate,
		IfaceIP:  c.vpnNode.ifaceIP.String(),
		Peers:    []PeerCfg{},
	}

	for _, address := range c.vpnNode.node.Status.Addresses {
		if address.Type == corev1.NodeInternalIP {
			mainConfig.Endpoint = fmt.Sprintf("%s:%d", address.Address, 51820)
		}
	}

	for _, peer := range c.peers {
		if peer.isComplete() && peer.node.Name != c.vpnNode.node.Name {
			peerCfg := PeerCfg{
				IfaceIP: peer.ifaceIP.String(),
				PubKey:  peer.certificate,
			}
			mainConfig.Peers = append(mainConfig.Peers, peerCfg)
		}
	}

	bytes, err := json.Marshal(mainConfig)
	if err != nil {
		logger.Error(err, "unable to encode main config", "config", mainConfig)
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: controllerMainconfigName,
		},
		Data: map[string]string{
			"mainConfig": string(bytes),
		},
	}
	logger.Info("main configuration", cm)

	_, err = c.kubeclientset.CoreV1().ConfigMaps(controllerNamespace).Get(ctx, controllerMainconfigName, v1.GetOptions{})
	if errors.IsNotFound(err) {
		_, err := c.kubeclientset.CoreV1().ConfigMaps(controllerNamespace).Create(ctx, cm, metav1.CreateOptions{})
		if err != nil {
			logger.Error(err, "unable to create mainconfig")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
	} else if err != nil {
		logger.Error(err, "unable to locate a potentially existing mainconfig")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	} else {
		patch := map[string]interface{}{
			"data": map[string]interface{}{
				"mainConfig": cm.Data["mainConfig"],
			},
		}

		patchBytes, err := json.Marshal(patch)
		if err != nil {
			logger.Error(err, "failed generate json output")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}

		_, err = c.kubeclientset.CoreV1().ConfigMaps(controllerNamespace).Patch(ctx, controllerMainconfigName, types.MergePatchType, patchBytes, metav1.PatchOptions{})
		if err != nil {
			logger.Error(err, "unable to update node")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
	}

	return nil
}

func (c *Controller) maybeUpdateMainConfig(ctx context.Context) error {
	if c.vpnNode != nil {
		return c.updateMainConfig(ctx)
	}

	return nil
}

func (c *Controller) onCertChanged(ctx context.Context, cm *corev1.ConfigMap) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "cm", cm.Name)

	// first make sure the certificate is one of the nodes
	nodeList, err := c.kubeclientset.CoreV1().Nodes().List(ctx, v1.ListOptions{})
	if err != nil {
		logger.Error(err, "unable to create mainconfig")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	found := false
	for _, node := range nodeList.Items {
		if node.Name == cm.Name {
			found = true
			break
		}
	}

	if !found {
		return nil
	}

	peer, ok := c.peers[cm.Name]
	if !ok {
		peer = &NodeInfo{}
	}

	peer.certificate = cm.Data["pubKey"]
	c.peers[cm.Name] = peer

	c.maybeUpdateMainConfig(ctx)

	return nil
}

func getBroadcastAddress(ipNet *net.IPNet) net.IP {
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil
	}

	broadcast := make(net.IP, len(ip))
	for i := 0; i < len(ip); i++ {
		broadcast[i] = ip[i] | ^ipNet.Mask[i]
	}

	return broadcast
}

func (c *Controller) allocateIP(ctx context.Context) (net.IP, error) {
	logger := klog.LoggerWithValues(klog.FromContext(ctx))

	nodeList, err := c.kubeclientset.CoreV1().Nodes().List(ctx, v1.ListOptions{})
	if err != nil {
		logger.Error(err, "unable to create mainconfig")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	usedIPs := map[string]int{}
	for _, node := range nodeList.Items {
		addr, ok := node.Annotations["wg-roaming.k8s.io/addr"]
		if ok {
			nodeIP := net.ParseIP(addr)
			if nodeIP == nil {
				return nil, fmt.Errorf("invalid node IP, node=%s ip=%s", node.Name, addr)
			}

			usedIPs[nodeIP.String()] = 0
		}
	}

	_, vpnSubnet, err := net.ParseCIDR(vpnCIDR)
	if err != nil {
		logger.Error(err, "invalid vpn CIDR")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	ip := vpnSubnet.IP.Mask(vpnSubnet.Mask)
	ip[len(ip)-1]++

	broadcastAddr := getBroadcastAddress(vpnSubnet)
	if broadcastAddr == nil {
		logger.Error(err, "unable to get broadcast address")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	for ; vpnSubnet.Contains(ip) && !ip.Equal(broadcastAddr); incrementIP(ip) {
		_, used := usedIPs[ip.String()]
		if !used {
			return ip, nil
		}
	}

	return nil, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (c *Controller) onNodesChanged(ctx context.Context, event NodeEvent) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "node", event.node.Name)

	// 1. if node is vpn node, set mainconfig to point to this node
	// 2. if node is not vpn node, wait for the node's configmap containing it's public key
	//  2.1 when public key found, add new peer with public key

	var ip net.IP
	existingIp, ok := event.node.Annotations["wg-roaming.k8s.io/addr"]
	if ok {
		ip = net.ParseIP(existingIp)
		if ip == nil {
			logger.Error(nil, "invalid ip in node annotation", "node", event.node.Name, "ip", existingIp)
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
	} else {
		ip, err := c.allocateIP(ctx)
		if err != nil || ip == nil {
			logger.Error(err, "unable to allocate ip")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
		patch := map[string]interface{}{
			"metadata": map[string]interface{}{
				"annotations": map[string]interface{}{
					"wg-roaming.k8s.io/addr": ip.String(),
				},
			},
		}

		patchBytes, err := json.Marshal(patch)
		if err != nil {
			logger.Error(err, "failed generate json output")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}

		_, err = c.kubeclientset.CoreV1().Nodes().Patch(ctx, event.node.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{})
		if err != nil {
			logger.Error(err, "unable to update node")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
	}

	peer, ok := c.peers[event.node.Name]
	if !ok {
		peer = &NodeInfo{}
	}

	peer.node = event.node
	peer.ifaceIP = ip
	c.peers[event.node.Name] = peer

	_, ok = event.node.Annotations["wg-roaming.k8s.io/server"]
	if ok {
		c.vpnNode = peer
	}

	c.maybeUpdateMainConfig(ctx)

	return nil
}
