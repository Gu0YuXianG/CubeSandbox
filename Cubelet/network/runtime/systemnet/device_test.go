// Copyright (c) 2024 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0
//

package systemnet

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestWithDumpRetrySucceedsAfterInterrupt(t *testing.T) {
	calls := 0
	got, err := WithDumpRetry(func() (int, error) {
		calls++
		if calls < 3 {
			return 0, netlink.ErrDumpInterrupted
		}
		return 42, nil
	})
	require.NoError(t, err)
	assert.Equal(t, 42, got)
	assert.Equal(t, 3, calls)
}

func TestWithDumpRetryExhaustsAttempts(t *testing.T) {
	calls := 0
	_, err := WithDumpRetry(func() (int, error) {
		calls++
		return 0, netlink.ErrDumpInterrupted
	})
	require.ErrorIs(t, err, netlink.ErrDumpInterrupted)
	assert.Equal(t, maxDumpRetries, calls)
}

func TestWithDumpRetryDoesNotRetryOtherErrors(t *testing.T) {
	want := errors.New("not a dump interrupt")
	calls := 0
	_, err := WithDumpRetry(func() (int, error) {
		calls++
		return 0, want
	})
	require.ErrorIs(t, err, want)
	assert.Equal(t, 1, calls)
}

func TestWithDumpRetryTreatsEINTRAsInterrupt(t *testing.T) {
	calls := 0
	got, err := WithDumpRetry(func() (string, error) {
		calls++
		if calls == 1 {
			return "", unix.EINTR
		}
		return "ok", nil
	})
	require.NoError(t, err)
	assert.Equal(t, "ok", got)
	assert.Equal(t, 2, calls)
}

func TestLookupGatewayMacFindsUsableNeighbor(t *testing.T) {
	gwIP := net.ParseIP("192.168.1.1")
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	origNeighList := netlinkNeighList
	t.Cleanup(func() { netlinkNeighList = origNeighList })

	netlinkNeighList = func(linkIndex, family int) ([]netlink.Neigh, error) {
		return []netlink.Neigh{
			{IP: gwIP, HardwareAddr: mac, Family: netlink.FAMILY_V4, State: unix.NUD_REACHABLE},
		}, nil
	}
	got, err := lookupGatewayMac(1, gwIP)
	require.NoError(t, err)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", got)
}

func TestLookupGatewayMacSkipsIncomplete(t *testing.T) {
	gwIP := net.ParseIP("192.168.1.1")
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	origNeighList := netlinkNeighList
	t.Cleanup(func() { netlinkNeighList = origNeighList })

	netlinkNeighList = func(linkIndex, family int) ([]netlink.Neigh, error) {
		return []netlink.Neigh{
			{IP: gwIP, HardwareAddr: mac, Family: netlink.FAMILY_V4, State: unix.NUD_INCOMPLETE},
		}, nil
	}
	_, err := lookupGatewayMac(1, gwIP)
	require.Error(t, err)
}

func TestGetGatewayMacAddrReturnsImmediatelyWhenCached(t *testing.T) {
	gwIP := net.ParseIP("10.0.0.1")
	mac, _ := net.ParseMAC("de:ad:be:ef:00:01")

	origNeighList := netlinkNeighList
	origLinkByName := netlinkLinkByName
	origRouteList := netlinkRouteList
	origTriggerARP := triggerARPResolution
	t.Cleanup(func() {
		netlinkNeighList = origNeighList
		netlinkLinkByName = origLinkByName
		netlinkRouteList = origRouteList
		triggerARPResolution = origTriggerARP
	})

	fakeLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 5, Name: "ens3"}}
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		return fakeLink, nil
	}
	netlinkRouteList = func(link netlink.Link, family int) ([]netlink.Route, error) {
		return []netlink.Route{{Dst: nil, Gw: gwIP, Priority: 100}}, nil
	}
	netlinkNeighList = func(linkIndex, family int) ([]netlink.Neigh, error) {
		return []netlink.Neigh{
			{IP: gwIP, HardwareAddr: mac, Family: netlink.FAMILY_V4, State: unix.NUD_REACHABLE},
		}, nil
	}

	arpCalls := 0
	triggerARPResolution = func(ifName string, ip net.IP) {
		arpCalls++
	}

	got, err := GetGatewayMacAddr("ens3")
	require.NoError(t, err)
	assert.Equal(t, "de:ad:be:ef:00:01", got)
	assert.Equal(t, 0, arpCalls, "ARP should not be triggered when cache hits on first try")
}

func TestGetGatewayMacAddrRetriesOnCacheMiss(t *testing.T) {
	gwIP := net.ParseIP("10.0.0.1")
	mac, _ := net.ParseMAC("de:ad:be:ef:00:01")

	// Save originals and restore after test.
	origNeighList := netlinkNeighList
	origLinkByName := netlinkLinkByName
	origRouteList := netlinkRouteList
	origTriggerARP := triggerARPResolution
	t.Cleanup(func() {
		netlinkNeighList = origNeighList
		netlinkLinkByName = origLinkByName
		netlinkRouteList = origRouteList
		triggerARPResolution = origTriggerARP
	})

	// Stub link.
	fakeLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 5, Name: "ens3"}}
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		return fakeLink, nil
	}
	// Stub default route.
	netlinkRouteList = func(link netlink.Link, family int) ([]netlink.Route, error) {
		return []netlink.Route{{Dst: nil, Gw: gwIP, Priority: 100}}, nil
	}

	// Simulate ARP cache miss for first 2 calls, then succeed.
	neighCalls := 0
	netlinkNeighList = func(linkIndex, family int) ([]netlink.Neigh, error) {
		neighCalls++
		if neighCalls <= 2 {
			return nil, nil // empty neighbor table
		}
		return []netlink.Neigh{
			{IP: gwIP, HardwareAddr: mac, Family: netlink.FAMILY_V4, State: unix.NUD_REACHABLE},
		}, nil
	}

	arpCalls := 0
	triggerARPResolution = func(ifName string, ip net.IP) {
		arpCalls++
	}

	got, err := GetGatewayMacAddr("ens3")
	require.NoError(t, err)
	assert.Equal(t, "de:ad:be:ef:00:01", got)
	assert.Equal(t, 2, arpCalls, "ARP should have been triggered twice")
	assert.Equal(t, 3, neighCalls, "neighbor table should have been queried 3 times")
}

func TestGetGatewayMacAddrFailsAfterAllRetries(t *testing.T) {
	gwIP := net.ParseIP("10.0.0.1")

	origNeighList := netlinkNeighList
	origLinkByName := netlinkLinkByName
	origRouteList := netlinkRouteList
	origTriggerARP := triggerARPResolution
	t.Cleanup(func() {
		netlinkNeighList = origNeighList
		netlinkLinkByName = origLinkByName
		netlinkRouteList = origRouteList
		triggerARPResolution = origTriggerARP
	})

	fakeLink := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 5, Name: "ens3"}}
	netlinkLinkByName = func(name string) (netlink.Link, error) {
		return fakeLink, nil
	}
	netlinkRouteList = func(link netlink.Link, family int) ([]netlink.Route, error) {
		return []netlink.Route{{Dst: nil, Gw: gwIP, Priority: 100}}, nil
	}
	// Neighbor table is always empty.
	netlinkNeighList = func(linkIndex, family int) ([]netlink.Neigh, error) {
		return nil, nil
	}

	arpCalls := 0
	triggerARPResolution = func(ifName string, ip net.IP) {
		arpCalls++
	}

	_, err := GetGatewayMacAddr("ens3")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway mac for ens3 via 10.0.0.1 not found")
	assert.Equal(t, gatewayARPRetries, arpCalls, "ARP should be triggered on every retry")
}

func TestProbeNeighborEntryReturnsTrueWhenMacExists(t *testing.T) {
	gwIP := net.ParseIP("192.168.1.1")
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	origNeighSet := netlinkNeighSet
	origNeighList := netlinkNeighList
	t.Cleanup(func() {
		netlinkNeighSet = origNeighSet
		netlinkNeighList = origNeighList
	})

	netlinkNeighSet = func(neigh *netlink.Neigh) error {
		return nil
	}
	netlinkNeighList = func(linkIndex, family int) ([]netlink.Neigh, error) {
		return []netlink.Neigh{
			{IP: gwIP, HardwareAddr: mac, Family: netlink.FAMILY_V4, State: unix.NUD_STALE},
		}, nil
	}

	assert.True(t, probeNeighborEntry(1, gwIP))
}

func TestProbeNeighborEntryReturnsFalseWhenNoMac(t *testing.T) {
	gwIP := net.ParseIP("192.168.1.1")

	origNeighSet := netlinkNeighSet
	origNeighList := netlinkNeighList
	t.Cleanup(func() {
		netlinkNeighSet = origNeighSet
		netlinkNeighList = origNeighList
	})

	netlinkNeighSet = func(neigh *netlink.Neigh) error {
		return nil
	}
	netlinkNeighList = func(linkIndex, family int) ([]netlink.Neigh, error) {
		return []netlink.Neigh{
			{IP: gwIP, HardwareAddr: nil, Family: netlink.FAMILY_V4, State: unix.NUD_PROBE},
		}, nil
	}

	assert.False(t, probeNeighborEntry(1, gwIP))
}

func TestProbeNeighborEntryReturnsFalseOnError(t *testing.T) {
	gwIP := net.ParseIP("192.168.1.1")

	origNeighSet := netlinkNeighSet
	t.Cleanup(func() { netlinkNeighSet = origNeighSet })

	netlinkNeighSet = func(neigh *netlink.Neigh) error {
		return errors.New("permission denied")
	}

	assert.False(t, probeNeighborEntry(1, gwIP))
}

func TestRemoveEmptyNeighborEntryDeletesEmpty(t *testing.T) {
	gwIP := net.ParseIP("192.168.1.1")

	origNeighList := netlinkNeighList
	origNeighDel := netlinkNeighDel
	t.Cleanup(func() {
		netlinkNeighList = origNeighList
		netlinkNeighDel = origNeighDel
	})

	netlinkNeighList = func(linkIndex, family int) ([]netlink.Neigh, error) {
		return []netlink.Neigh{
			{IP: gwIP, HardwareAddr: nil, Family: netlink.FAMILY_V4, State: unix.NUD_PROBE},
		}, nil
	}

	delCalls := 0
	netlinkNeighDel = func(neigh *netlink.Neigh) error {
		delCalls++
		return nil
	}

	removeEmptyNeighborEntry(1, gwIP)
	assert.Equal(t, 1, delCalls)
}

func TestRemoveEmptyNeighborEntrySkipsEntryWithMac(t *testing.T) {
	gwIP := net.ParseIP("192.168.1.1")
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	origNeighList := netlinkNeighList
	origNeighDel := netlinkNeighDel
	t.Cleanup(func() {
		netlinkNeighList = origNeighList
		netlinkNeighDel = origNeighDel
	})

	netlinkNeighList = func(linkIndex, family int) ([]netlink.Neigh, error) {
		return []netlink.Neigh{
			{IP: gwIP, HardwareAddr: mac, Family: netlink.FAMILY_V4, State: unix.NUD_STALE},
		}, nil
	}

	delCalls := 0
	netlinkNeighDel = func(neigh *netlink.Neigh) error {
		delCalls++
		return nil
	}

	removeEmptyNeighborEntry(1, gwIP)
	assert.Equal(t, 0, delCalls, "should not delete entry that has a MAC")
}
