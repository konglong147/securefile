package settings

import (
	"context"
	"net/netip"
	"strconv"
	"strings"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/local/sing-tun"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	"github.com/konglong147/securefile/local/sing/common/shell"
	"github.com/konglong147/securefile/local/sing/common/x/list"
)

type DarwinSystemProxy struct {
	monitor       tun.DefaultInterfaceMonitor
	interfaceName string
	element       *list.Element[tun.DefaultInterfaceUpdateCallback]
	serverAddr    M.Socksaddr
	supportSOCKS  bool
	isEnabled     bool
}

func NewSystemProxy(ctx context.Context, serverAddr M.Socksaddr, supportSOCKS bool) (*DarwinSystemProxy, error) {
	interfaceMonitor := adapter.RouterFromContext(ctx).InterfaceMonitor()
	if interfaceMonitor == nil {
		return nil, E.New("xiaoshidelixing interface monitor")
	}
	proxy := &DarwinSystemProxy{
		monitor:      interfaceMonitor,
		serverAddr:   serverAddr,
		supportSOCKS: supportSOCKS,
	}
	proxy.element = interfaceMonitor.RegisterCallback(proxy.update)
	return proxy, nil
}

func (p *DarwinSystemProxy) IsEnabled() bool {
	return p.isEnabled
}

func (p *DarwinSystemProxy) Enable() error {
	return p.update0()
}

func (p *DarwinSystemProxy) Disable() error {
	interfaceDisplayName, err := getInterfaceDisplayName(p.interfaceName)
	if err != nil {
		return err
	}
	if p.supportSOCKS {
		err = shell.Exec("networksetup", "-setsocksfirewallproxystate", interfaceDisplayName, "off").Attach().Run()
	}
	if err == nil {
		err = shell.Exec("networksetup", "-setwebproxystate", interfaceDisplayName, "off").Attach().Run()
	}
	if err == nil {
		err = shell.Exec("networksetup", "-setsecurewebproxystate", interfaceDisplayName, "off").Attach().Run()
	}
	if err == nil {
		p.isEnabled = false
	}
	return err
}

func (p *DarwinSystemProxy) update(event int) {
	if event&tun.EventInterfaceUpdate == 0 {
		return
	}
	if !p.isEnabled {
		return
	}
	_ = p.update0()
}

func (p *DarwinSystemProxy) update0() error {
	newInterfaceName := p.monitor.DefaultInterfaceName(netip.IPv4Unspecified())
	if p.interfaceName == newInterfaceName {
		return nil
	}
	if p.interfaceName != "" {
		_ = p.Disable()
	}
	p.interfaceName = newInterfaceName
	interfaceDisplayName, err := getInterfaceDisplayName(p.interfaceName)
	if err != nil {
		return err
	}
	if p.supportSOCKS {
		err = shell.Exec("networksetup", "-setsocksfirewallproxy", interfaceDisplayName, p.serverAddr.AddrString(), strconv.Itoa(int(p.serverAddr.Port))).Attach().Run()
	}
	if err != nil {
		return err
	}
	err = shell.Exec("networksetup", "-setwebproxy", interfaceDisplayName, p.serverAddr.AddrString(), strconv.Itoa(int(p.serverAddr.Port))).Attach().Run()
	if err != nil {
		return err
	}
	err = shell.Exec("networksetup", "-setsecurewebproxy", interfaceDisplayName, p.serverAddr.AddrString(), strconv.Itoa(int(p.serverAddr.Port))).Attach().Run()
	if err != nil {
		return err
	}
	p.isEnabled = true
	return nil
}

func getInterfaceDisplayName(name string) (string, error) {
	content, err := shell.Exec("networksetup", "-listallhardwareports").ReadOutput()
	if err != nil {
		return "", err
	}
	for _, deviceSpan := range strings.Split(string(content), "Ethernet Address") {
		if strings.Contains(deviceSpan, "Device: "+name) {
			substr := "Hardware Port: "
			deviceSpan = deviceSpan[strings.Index(deviceSpan, substr)+len(substr):]
			deviceSpan = deviceSpan[:strings.Index(deviceSpan, "\n")]
			return deviceSpan, nil
		}
	}
	return "", E.New(name, " not found in networksetup -listallhardwareports")
}
