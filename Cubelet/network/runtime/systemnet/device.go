// Copyright (c) 2024 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0
//

package systemnet

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// gatewayARPRetries is the number of times GetGatewayMacAddr will re-probe the
// neighbor table after triggering ARP resolution. Node initialization may race
// the kernel's ARP learning, so a single read is not enough.
const gatewayARPRetries = 5

// gatewayARPBackoff is the delay between ARP trigger retries. It gives the
// kernel time to complete the ARP request/response cycle.
const gatewayARPBackoff = 200 * time.Millisecond

// maxDumpRetries is higher than containernetworking/plugins netlinksafe (5)
// because Cubelet density creates can keep the link table mutating for longer
// than a single LinkList of hundreds of TAPs takes to complete.
const maxDumpRetries = 16

// dumpRetryBackoff is a short pause between interrupted dumps so concurrent
// LinkAdd/LinkDel traffic can settle before the next attempt.
const dumpRetryBackoff = 2 * time.Millisecond

var (
	// Package-level function variables are test seams for host networking helpers.
	// Dump-style reads go through WithDumpRetry so NLM_F_DUMP_INTR under TAP
	// churn is retried; mutating calls are left unwrapped.
	netlinkRouteReplace      = netlink.RouteReplace
	netlinkRouteListFiltered = func(family int, filter *netlink.Route, mask uint64) ([]netlink.Route, error) {
		return WithDumpRetry(func() ([]netlink.Route, error) {
			return netlink.RouteListFiltered(family, filter, mask)
		})
	}
	netlinkRouteList = func(link netlink.Link, family int) ([]netlink.Route, error) {
		return WithDumpRetry(func() ([]netlink.Route, error) {
			return netlink.RouteList(link, family)
		})
	}
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		return WithDumpRetry(func() (netlink.Link, error) {
			return netlink.LinkByName(name)
		})
	}
	netlinkLinkList = func() ([]netlink.Link, error) {
		return WithDumpRetry(netlink.LinkList)
	}
	netlinkLinkDel   = netlink.LinkDel
	netlinkNeighList = func(linkIndex, family int) ([]netlink.Neigh, error) {
		return WithDumpRetry(func() ([]netlink.Neigh, error) {
			return netlink.NeighList(linkIndex, family)
		})
	}
	netlinkAddrList = func(link netlink.Link, family int) ([]netlink.Addr, error) {
		return WithDumpRetry(func() ([]netlink.Addr, error) {
			return netlink.AddrList(link, family)
		})
	}
	netlinkRouteDel = netlink.RouteDel
	netlinkNeighSet  = netlink.NeighSet
	netlinkNeighDel  = netlink.NeighDel

	// triggerARPResolution forces the kernel to resolve the gateway's L2
	// address. It first tries NeighSet(NUD_PROBE) to re-probe an existing
	// neighbor entry. If that creates an empty entry instead, it cleans up
	// and falls back to a UDP probe.
	triggerARPResolution = func(ifName string, gatewayIP net.IP) {
		link, err := netlinkLinkByName(ifName)
		if err != nil {
			return
		}
		if probeNeighborEntry(link.Attrs().Index, gatewayIP) {
			return // re-probed an existing entry that already has a MAC
		}
		removeEmptyNeighborEntry(link.Attrs().Index, gatewayIP)
		sendUDPProbe(gatewayIP)
	}
)

// probeNeighborEntry sets NUD_PROBE on the neighbor entry for gatewayIP.
// Returns true if the entry already had a MAC (i.e. it was an existing entry
// being re-probed, so the kernel will send ARP). Returns false if no entry
// existed or the entry has no MAC yet.
func probeNeighborEntry(linkIndex int, gatewayIP net.IP) bool {
	if err := netlinkNeighSet(&netlink.Neigh{
		IP:           gatewayIP,
		LinkIndex:    linkIndex,
		State:        unix.NUD_PROBE,
		Family:       netlink.FAMILY_V4,
	}); err != nil {
		return false
	}
	neighs, err := netlinkNeighList(linkIndex, netlink.FAMILY_V4)
	if err != nil {
		return false
	}
	for _, n := range neighs {
		if n.IP.Equal(gatewayIP) && len(n.HardwareAddr) > 0 {
			return true
		}
	}
	return false
}

// removeEmptyNeighborEntry deletes a neighbor entry that has no MAC address.
// This cleans up the empty NUD_PROBE entry that NeighSet may have created
// when no prior entry existed, preventing it from interfering with lookups.
func removeEmptyNeighborEntry(linkIndex int, gatewayIP net.IP) {
	neighs, err := netlinkNeighList(linkIndex, netlink.FAMILY_V4)
	if err != nil {
		return
	}
	for _, n := range neighs {
		if n.IP.Equal(gatewayIP) && len(n.HardwareAddr) == 0 {
			_ = netlinkNeighDel(&n)
			return
		}
	}
}

// sendUDPProbe sends a small UDP packet to gatewayIP, forcing the kernel to
// create a neighbor entry and issue an ARP request through the network stack.
func sendUDPProbe(gatewayIP net.IP) {
	conn, err := net.DialTimeout("udp4", gatewayIP.String()+":1", 100*time.Millisecond)
	if err != nil {
		return
	}
	_, _ = conn.Write([]byte{0})
	conn.Close()
}

// HostDevice captures the configured host network device selected by Cubelet.
type HostDevice struct {
	Index      int
	Name       string
	IP         net.IP
	IPMask     net.IPMask
	Mac        net.HardwareAddr
	GatewayMac net.HardwareAddr
}

// GetHostDevice validates the configured host interface and captures the
// addresses CubeVS needs for SNAT and L2 forwarding.
func GetHostDevice(ifName string) (*HostDevice, error) {
	link, err := netlinkLinkByName(ifName)
	if err != nil {
		return nil, err
	}
	addrs, err := netlinkAddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	if len(addrs) != 1 {
		return nil, fmt.Errorf("ipv4 address on %s is not unique", ifName)
	}
	gwMac, err := GetGatewayMacAddr(ifName)
	if err != nil {
		return nil, err
	}
	gatewayMac, err := net.ParseMAC(gwMac)
	if err != nil {
		return nil, err
	}
	return &HostDevice{
		Index:      link.Attrs().Index,
		Name:       link.Attrs().Name,
		IP:         addrs[0].IP,
		IPMask:     addrs[0].Mask,
		Mac:        link.Attrs().HardwareAddr,
		GatewayMac: gatewayMac,
	}, nil
}

// GetGatewayMacAddr resolves the MAC address of the default gateway on ifName
// from the neighbor table. CubeVS needs this L2 destination for direct egress.
// When the neighbor entry has not been learned yet (common during node boot),
// it triggers ARP resolution and retries with a short backoff.
func GetGatewayMacAddr(ifName string) (string, error) {
	link, err := netlinkLinkByName(ifName)
	if err != nil {
		return "", err
	}
	gatewayIP, err := defaultGatewayIP(link)
	if err != nil {
		return "", err
	}

	// First attempt: read whatever the neighbor table already has.
	if mac, err := lookupGatewayMac(link.Attrs().Index, gatewayIP); err == nil {
		return mac, nil
	}

	// Cache miss: actively trigger ARP and retry. During node initialization
	// the gateway's neighbor entry may not exist yet; triggerARPResolution
	// first tries NeighSet(NUD_PROBE) then falls back to a UDP probe.
	for attempt := 0; attempt < gatewayARPRetries; attempt++ {
		triggerARPResolution(ifName, gatewayIP)
		time.Sleep(gatewayARPBackoff)
		if mac, err := lookupGatewayMac(link.Attrs().Index, gatewayIP); err == nil {
			return mac, nil
		}
	}
	return "", fmt.Errorf("gateway mac for %s via %s not found", ifName, gatewayIP.String())
}

// lookupGatewayMac scans the neighbor table on linkIndex for a usable entry
// matching gatewayIP.
func lookupGatewayMac(linkIndex int, gatewayIP net.IP) (string, error) {
	neighs, err := netlinkNeighList(linkIndex, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}
	for _, neigh := range neighs {
		if isUsableGatewayNeighbor(neigh, gatewayIP) {
			return neigh.HardwareAddr.String(), nil
		}
	}
	return "", fmt.Errorf("gateway mac not found")
}

// defaultGatewayIP chooses the lowest-metric IPv4 default route on link.
func defaultGatewayIP(link netlink.Link) (net.IP, error) {
	routes, err := netlinkRouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	var gatewayIP net.IP
	var gatewayMetric int
	for _, route := range routes {
		if !isIPv4DefaultRoute(route.Dst) || route.Gw.To4() == nil {
			continue
		}
		if gatewayIP == nil || route.Priority < gatewayMetric {
			gatewayIP = route.Gw.To4()
			gatewayMetric = route.Priority
		}
	}
	if gatewayIP == nil {
		return nil, fmt.Errorf("default gateway not found on %s", link.Attrs().Name)
	}
	return gatewayIP, nil
}

// isIPv4DefaultRoute reports whether dst represents 0.0.0.0/0.
func isIPv4DefaultRoute(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, bits := dst.Mask.Size()
	return bits == 32 && ones == 0
}

// isUsableGatewayNeighbor accepts reachable or recoverable neighbor states for
// the selected gateway. Failed/incomplete entries are ignored.
func isUsableGatewayNeighbor(neigh netlink.Neigh, gatewayIP net.IP) bool {
	if neigh.Family != netlink.FAMILY_V4 || !neigh.IP.Equal(gatewayIP) || len(neigh.HardwareAddr) == 0 {
		return false
	}
	switch neigh.State {
	case unix.NUD_REACHABLE, unix.NUD_STALE, unix.NUD_DELAY, unix.NUD_PROBE, unix.NUD_PERMANENT:
		return true
	default:
		return false
	}
}

// WithDumpRetry runs op, retrying when a netlink dump was interrupted because
// the table changed mid-read (ErrDumpInterrupted / EINTR). Other errors and
// success return immediately. Mutating netlink calls should not use this.
func WithDumpRetry[T any](op func() (T, error)) (T, error) {
	var (
		zero T
		last error
	)
	for attempt := 0; attempt < maxDumpRetries; attempt++ {
		v, err := op()
		if err == nil || !isDumpInterrupted(err) {
			return v, err
		}
		last = err
		if attempt+1 < maxDumpRetries {
			time.Sleep(dumpRetryBackoff)
		}
	}
	return zero, last
}

func isDumpInterrupted(err error) bool {
	return errors.Is(err, netlink.ErrDumpInterrupted) || errors.Is(err, unix.EINTR)
}
