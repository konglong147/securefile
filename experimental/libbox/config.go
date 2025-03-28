package Foxboxvpn

import (
	"bytes"
	"context"
	"net/netip"
	"os"

	"github.com/konglong147/securefile"
	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/common/process"
	"github.com/konglong147/securefile/experimental/libbox/platform"
	"github.com/konglong147/securefile/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

func parseConfig(configContent string) (option.Options, error) {
	options, err := json.UnmarshalExtended[option.Options]([]byte(configContent))
	if err != nil {
		return option.Options{}, E.Cause(err, "decode config")
	}
	return options, nil
}

func CheckConfig(configContent string) error {
	options, err := parseConfig(configContent)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance, err := box.New(box.Options{
		Context:           ctx,
		Options:           options,
		PlatformInterface: (*platformInterfaceStub)(nil),
	})
	if err == nil {
		instance.Close()
	}
	return err
}

type platformInterfaceStub struct{}

func (s *platformInterfaceStub) Initialize(ctx context.Context, router adapter.Router) error {
	return nil
}

func (s *platformInterfaceStub) UsePlatformAutoDetectInterfaceControl() bool {
	return true
}

func (s *platformInterfaceStub) AutoDetectInterfaceControl(fd int) error {
	return nil
}

func (s *platformInterfaceStub) OpenTun(options *tun.Options, platformOptions option.TunPlatformOptions) (tun.Tun, error) {
	return nil, os.ErrInvalid
}

func (s *platformInterfaceStub) UsePlatformDefaultInterfaceMonitor() bool {
	return true
}

func (s *platformInterfaceStub) CreateDefaultInterfaceMonitor(logger logger.Logger) tun.DefaultInterfaceMonitor {
	return (*interfaceMonitorStub)(nil)
}

func (s *platformInterfaceStub) UsePlatformInterfaceGetter() bool {
	return true
}

func (s *platformInterfaceStub) Interfaces() ([]control.Interface, error) {
	return nil, os.ErrInvalid
}

func (s *platformInterfaceStub) UnderNetworkExtension() bool {
	return false
}

func (s *platformInterfaceStub) IncludeAllNetworks() bool {
	return false
}

func (s *platformInterfaceStub) ClearDNSCache() {
}

func (s *platformInterfaceStub) ReadWIFIState() adapter.WIFIState {
	return adapter.WIFIState{}
}

func (s *platformInterfaceStub) FindProcessInfo(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*process.Info, error) {
	return nil, os.ErrInvalid
}

type interfaceMonitorStub struct{}

func (s *interfaceMonitorStub) Start() error {
	return os.ErrInvalid
}

func (s *interfaceMonitorStub) Close() error {
	return os.ErrInvalid
}

func (s *interfaceMonitorStub) DefaultInterfaceName(destination netip.Addr) string {
	return ""
}

func (s *interfaceMonitorStub) DefaultInterfaceIndex(destination netip.Addr) int {
	return -1
}

func (s *interfaceMonitorStub) DefaultInterface(destination netip.Addr) (string, int) {
	return "", -1
}

func (s *interfaceMonitorStub) OverrideAndroidVPN() bool {
	return false
}

func (s *interfaceMonitorStub) AndroidVPNEnabled() bool {
	return false
}

func (s *interfaceMonitorStub) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return nil
}

func (s *interfaceMonitorStub) UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback]) {
}

func (s *platformInterfaceStub) SendNotification(notification *platform.Notification) error {
	return nil
}

func FormatConfig(configContent string) (*StringBox, error) {
	options, err := parseConfig(configContent)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(options)
	if err != nil {
		return nil, err
	}
	return wrapString(buffer.String()), nil
}
