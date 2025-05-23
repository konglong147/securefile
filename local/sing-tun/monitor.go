package tun

import (
	"net/netip"

	"github.com/konglong147/securefile/local/sing/common/control"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	"github.com/konglong147/securefile/local/sing/common/x/list"
)

var ErrNoRoute = E.New("no route to internet")

type (
	NetworkUpdateCallback          = func()
	DefaultInterfaceUpdateCallback = func(event int)
)

const (
	EventInterfaceUpdate  = 1
	EventAndroidVPNUpdate = 2
	EventNoRoute          = 4
)

type NetworkUpdateMonitor interface {
	Start() error
	Close() error
	RegisterCallback(callback NetworkUpdateCallback) *list.Element[NetworkUpdateCallback]
	UnregisterCallback(element *list.Element[NetworkUpdateCallback])
}

type DefaultInterfaceMonitor interface {
	Start() error
	Close() error
	DefaultInterfaceName(destination netip.Addr) string
	DefaultInterfaceIndex(destination netip.Addr) int
	DefaultInterface(destination netip.Addr) (string, int)
	OverrideAndroidVPN() bool
	AndroidVPNEnabled() bool
	RegisterCallback(callback DefaultInterfaceUpdateCallback) *list.Element[DefaultInterfaceUpdateCallback]
	UnregisterCallback(element *list.Element[DefaultInterfaceUpdateCallback])
}

type DefaultInterfaceMonitorOptions struct {
	InterfaceFinder       control.InterfaceFinder
	OverrideAndroidVPN    bool
	UnderNetworkExtension bool
}
