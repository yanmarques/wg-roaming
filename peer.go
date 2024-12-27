package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/vishvananda/netlink"
	"golang.org/x/time/rate"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

type Peer struct {
	// Wireguard keys
	key *wgtypes.Key

	nodeName string

	// kubeclientset is a standard kubernetes clientset
	kubeclientset kubernetes.Interface

	// processes configmap with certificate events
	workqueue workqueue.TypedRateLimitingInterface[*corev1.ConfigMap]

	sharedFactory kubeinformers.SharedInformerFactory

	cmInformer cache.SharedIndexInformer

	ifaceIP net.IP
}

func NewPeer(
	ctx context.Context,
	kubeClient kubernetes.Interface,
) *Peer {
	logger := klog.FromContext(ctx)

	ratelimiter := workqueue.NewTypedMaxOfRateLimiter(
		workqueue.NewTypedItemExponentialFailureRateLimiter[*corev1.ConfigMap](5*time.Millisecond, 1000*time.Second),
		&workqueue.TypedBucketRateLimiter[*corev1.ConfigMap]{Limiter: rate.NewLimiter(rate.Limit(50), 300)},
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

	peer := &Peer{
		kubeclientset: kubeClient,
		key:           key,
		nodeName:      nodeName,
		workqueue:     workqueue.NewTypedRateLimitingQueue(ratelimiter),
		sharedFactory: sharedFactory,
		cmInformer:    sharedFactory.Core().V1().ConfigMaps().Informer(),
	}

	// Set up event handlers for the node informer
	peer.cmInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cm := obj.(*corev1.ConfigMap)
			if IsMainConfig(cm) {
				peer.workqueue.Add(cm)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			cm := newObj.(*corev1.ConfigMap)
			if IsMainConfig(cm) {
				peer.workqueue.Add(cm)
			}
		},
	})

	return peer
}

func (p *Peer) Run(ctx context.Context) error {
	defer utilruntime.HandleCrash()
	defer p.workqueue.ShutDown()

	logger := klog.FromContext(ctx)

	err := PublishCert(ctx, p.kubeclientset, p.key, p.nodeName)
	if err != nil {
		logger.Error(err, "unable to publish certificate")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	// Wait for the caches to be synced before starting workers
	logger.Info("Waiting for informer caches to sync")

	p.sharedFactory.Start(ctx.Done())

	ok := cache.WaitForNamedCacheSync(controllerAgentName, ctx.Done(), p.cmInformer.HasSynced)
	if !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	// Start worker
	go wait.UntilWithContext(ctx, p.runWorker, time.Second)

	logger.Info("Started workers")
	<-ctx.Done()
	logger.Info("Shutting down workers")

	return nil
}

func (p *Peer) runWorker(ctx context.Context) {
	for p.processNextWorkItem(ctx) {
	}
}

func (p *Peer) processNextWorkItem(ctx context.Context) bool {
	cm, shutdown := p.workqueue.Get()
	logger := klog.FromContext(ctx)

	if shutdown {
		return false
	}

	defer p.workqueue.Done(cm)

	err := p.reconcile(ctx, cm)
	if err == nil {
		p.workqueue.Forget(cm)
		logger.Info("Successfully synced", "configMap", cm.Name)
		return false
	}

	utilruntime.HandleErrorWithContext(ctx, err, "Error syncing; requeuing for later retry", "configMap", cm.Name)
	p.workqueue.AddRateLimited(cm)

	return false
}

func (p *Peer) maybeRestartKubelet(ctx context.Context, vpnIP net.IP) error {
	logger := klog.FromContext(ctx)

	logger.Info("trying to restart kubelet")

	content, err := os.ReadFile("/etc/os-release")
	isFedora := false
	if err == nil {
		isFedora = strings.Contains(string(content), "Fedora")
	}
	logger.Info("is fedora", isFedora)

	var envPath string

	if isFedora {
		envPath = "/etc/sysconfig/kubelet"
	} else {
		envPath = "/etc/default/kubelet"
	}

	file, err := os.Open(envPath)
	kubeletLine := fmt.Sprintf("KUBELET_EXTRA_ARGS='--node-ip=%s'", vpnIP.String())

	if errors.Is(err, os.ErrNotExist) {
		file.Close()
		logger.Info("env file does not exist")
		if err := os.WriteFile(envPath, []byte(kubeletLine), os.FileMode(os.O_CREATE)); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		scanner := bufio.NewScanner(file)
		keptLines := []string{}

		for scanner.Scan() {
			line := scanner.Text()

			if kubeletLine == line {
				file.Close()
				return nil
			} else if !strings.HasPrefix(line, "KUBELET_EXTRA_ARGS='--node-ip=") {
				keptLines = append(keptLines, line)
			}
		}

		if err := scanner.Err(); err != nil {
			file.Close()
			return err
		}

		file.Close()

		logger.Info("env file already exists")
		content, err := os.ReadFile(envPath)
		if err != nil {
			return err
		}
		err = os.WriteFile(fmt.Sprintf("%s.bak", envPath), content, os.FileMode(os.O_CREATE))
		if err != nil {
			return err
		}

		keptLines = append(keptLines, kubeletLine)
		content = []byte(strings.Join(keptLines, "\n"))
		err = os.WriteFile(envPath, content, os.FileMode(os.O_CREATE))
		if err != nil {
			return err
		}
	}

	con, err := dbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		return err
	}

	defer con.Close()

	if err = con.ReloadContext(ctx); err != nil {
		return err
	}

	_, err = con.RestartUnitContext(ctx, "kubelet.service", "replace", nil)
	if err != nil {
		return err
	}

	return nil
}

func (p *Peer) reconcile(ctx context.Context, cm *corev1.ConfigMap) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "configMap", cm.Name)

	mainConfig := MainConfig{}
	err := json.Unmarshal([]byte(cm.Data["mainConfig"]), &mainConfig)
	if err != nil {
		logger.Error(err, "unable to unmarshal main config, giving up...")
		return err
	}

	routePeers := []net.IP{}

	vpnIP := net.ParseIP(mainConfig.IfaceIP)
	if vpnIP.IsUnspecified() {
		logger.Error(err, "invalid vpn IP", "ifaceIP", mainConfig.IfaceIP)
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	routePeers = append(routePeers, vpnIP)

	var ourIP net.IP
	ourPubKey := p.key.PublicKey().String()

	for _, peer := range mainConfig.Peers {
		peerIP := net.ParseIP(peer.IfaceIP)

		if peer.PubKey == ourPubKey {
			ourIP = peerIP
		} else {
			routePeers = append(routePeers, peerIP)
		}
	}

	if ourIP == nil {
		logger.Error(err, "unable to find this peer's CIDR network", "node", p.nodeName)
		return nil
	}

	if p.ifaceIP == nil || (p.ifaceIP != nil && !p.ifaceIP.Equal(ourIP)) {
		if err = p.maybeRestartKubelet(ctx, ourIP); err != nil {
			return err
		}
	}
	p.ifaceIP = ourIP

	client, err := wgctrl.New()
	if err != nil {
		return err
	}

	defer client.Close()

	la := netlink.NewLinkAttrs()
	la.Name = "wg0"
	la.MTU = 1500
	link := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}

	if err := ensureLink(ctx, link, &net.IPNet{IP: ourIP, Mask: net.IPv4Mask(255, 255, 255, 255)}); err != nil {
		logger.Error(err, "unable to configure network link")
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

	peerPubKey, err := wgtypes.ParseKey(mainConfig.PubKey)
	if err != nil {
		return err
	}

	peerAddr, err := net.ResolveUDPAddr("udp", mainConfig.Endpoint)
	if err != nil {
		return err
	}

	keepAlive := 15 * time.Second
	serverPeer := wgtypes.PeerConfig{
		PublicKey:                   peerPubKey,
		Endpoint:                    peerAddr,
		PersistentKeepaliveInterval: &keepAlive,
		Remove:                      false,
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  []net.IPNet{*vpnSubnet},
	}

	listenPort := 51820

	cfg := wgtypes.Config{
		PrivateKey:   p.key,
		ListenPort:   &listenPort,
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{serverPeer},
	}

	err = client.ConfigureDevice("wg0", cfg)
	if err != nil {
		logger.Error(err, "unable to configure wireguard device")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	logger.Info("configured device")

	return nil
}
