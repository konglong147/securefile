package tun

import (
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"

	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	F "github.com/konglong147/securefile/local/sing/common/format"
	"github.com/konglong147/securefile/local/sing/common/logger"
	N "github.com/konglong147/securefile/local/sing/common/network"
	"github.com/konglong147/securefile/local/sing/common/ranges"
)

type Handler interface {
	N.TCPConnectionHandler
	N.UDPConnectionHandler
	E.Handler
}

type Tun interface {
	io.ReadWriter
	N.VectorisedWriter
	Close() error
}

type WinTun interface {
	Tun
	ReadPacket() ([]byte, func(), error)
}

type LinuxTUN interface {
	Tun
	N.FrontHeadroom
	BatchSize() int
	BatchRead(buffers [][]byte, offset int, readN []int) (n int, err error)
	BatchWrite(buffers [][]byte, offset int) error
	TXChecksumOffload() bool
}

const (
	DefaultIPRoute2TableIndex = 2022
	DefaultIPRoute2RuleIndex  = 9000
)

type Options struct {
	Name                     string
	Inet4Address             []netip.Prefix
	Inet6Address             []netip.Prefix
	MTU                      uint32
	GSO                      bool
	AutoRoute                bool
	Inet4Gateway             netip.Addr
	Inet6Gateway             netip.Addr
	DNSServers               []netip.Addr
	IPRoute2TableIndex       int
	IPRoute2RuleIndex        int
	AutoRedirectMarkMode     bool
	AutoRedirectInputMark    uint32
	AutoRedirectOutputMark   uint32
	StrictRoute              bool
	Inet4RouteAddress        []netip.Prefix
	Inet6RouteAddress        []netip.Prefix
	Inet4RouteExcludeAddress []netip.Prefix
	Inet6RouteExcludeAddress []netip.Prefix
	IncludeInterface         []string
	ExcludeInterface         []string
	IncludeUID               []ranges.Range[uint32]
	ExcludeUID               []ranges.Range[uint32]
	IncludeAndroidUser       []int
	IncludePackage           []string
	ExcludePackage           []string
	InterfaceMonitor         DefaultInterfaceMonitor
	FileDescriptor           int
	Logger                   logger.Logger

	// No work for TCP, do not use.
	_TXChecksumOffload bool

	// For library usages.
	EXP_DisableDNSHijack bool
}

func (o *Options) Inet4GatewayAddr() netip.Addr {
	if o.Inet4Gateway.IsValid() {
		return o.Inet4Gateway
	}
	if len(o.Inet4Address) > 0 {
		switch runtime.GOOS {
		case "android":
		case "linux":
			if HasNextAddress(o.Inet4Address[0], 1) {
				return o.Inet4Address[0].Addr().Next()
			}
		case "darwin":
			return o.Inet4Address[0].Addr()
		default:
			if HasNextAddress(o.Inet4Address[0], 1) {
				return o.Inet4Address[0].Addr().Next()
			} else {
				return o.Inet4Address[0].Addr()
			}
		}
	}
	return netip.IPv4Unspecified()
}

func (o *Options) Inet6GatewayAddr() netip.Addr {
	if o.Inet6Gateway.IsValid() {
		return o.Inet6Gateway
	}
	if len(o.Inet6Address) > 0 {
		switch runtime.GOOS {
		case "android":
		case "linux":
			if HasNextAddress(o.Inet6Address[0], 1) {
				return o.Inet6Address[0].Addr().Next()
			}
		case "darwin":
			return o.Inet6Address[0].Addr()
		default:
			if HasNextAddress(o.Inet6Address[0], 1) {
				return o.Inet6Address[0].Addr().Next()
			} else {
				return o.Inet6Address[0].Addr()
			}
		}
	}
	return netip.IPv6Unspecified()
}

func CalculateInterfaceName(name string) (tunName string) {
	if runtime.GOOS == "darwin" {
		tunName = "utun"
	} else if name != "" {
		tunName = name
	} else {
		tunName = "tun"
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	var tunIndex int
	for _, netInterface := range interfaces {
		if strings.HasPrefix(netInterface.Name, tunName) {
			index, parseErr := strconv.ParseInt(netInterface.Name[len(tunName):], 10, 16)
			if parseErr == nil && int(index) >= tunIndex {
				tunIndex = int(index) + 1
			}
		}
	}
	tunName = F.ToString(tunName, tunIndex)
	return
}
