package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/klog/v2"
)

const wgPrivKeyPath = "/run/wireguard/wg-roaming.key"

type WireguardPeer struct {
	// Identifier used to find a Node
	nodeName string

	// Wireguard peerCIDR of node's peer
	peerCIDR *net.IPNet

	// Wireguard public key of node's peer
	pubKey  string
	privKey string
}

func grabWireguardKey() (*wgtypes.Key, error) {
	var key wgtypes.Key

	if _, err := os.Stat(wgPrivKeyPath); errors.Is(err, os.ErrNotExist) {
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}

		dir, _ := filepath.Split(wgPrivKeyPath)
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return nil, err
		}

		f, err := os.Create(wgPrivKeyPath)
		if err != nil {
			return nil, err
		}

		err = os.Chmod(wgPrivKeyPath, 0400)
		if err != nil {
			return nil, err
		}

		_, err = f.WriteString(key.String())
		if err != nil {
			return nil, err
		}

		f.Close()
	} else {
		content, err := os.ReadFile(wgPrivKeyPath)
		if err != nil {
			return nil, err
		}

		key, err = wgtypes.ParseKey(string(content))
		if err != nil {
			return nil, err
		}
	}

	return &key, nil
}

func ensureLink(ctx context.Context, wglan *netlink.GenericLink, netAddr *net.IPNet) error {
	err := netlink.LinkAdd(wglan)
	if err != nil && err != syscall.EEXIST {
		return fmt.Errorf("could not create wireguard interface: %w", err)
	}

	link, err := netlink.LinkByName(wglan.Name)
	if err != nil {
		return err
	}

	addr := &netlink.Addr{IPNet: netAddr, Label: ""}
	err = netlink.AddrReplace(link, addr)
	if err != nil {
		return err
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		return err
	}

	return nil
}

func upAndRoutes(ctx context.Context, link *netlink.GenericLink, peerCIDRs []net.IPNet) error {
	logger := klog.FromContext(ctx)

	err := netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("failed to set interface to UP state: dev=%s err=%s", link.Name, err)
	}

	for _, peerCIDR := range peerCIDRs {
		route := netlink.Route{
			LinkIndex: link.Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       &peerCIDR,
		}

		err = netlink.RouteAdd(&route)
		if err != nil && err != syscall.EEXIST {
			logger.Error(err, "failed to add route", "dest", peerCIDR.String())
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
	}

	return nil
}
