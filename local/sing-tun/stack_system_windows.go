package tun

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/konglong147/securefile/local/sing-tun/internal/winfw"

	"golang.org/x/sys/windows"
)

func fixWindowsFirewall() error {
	absPath, err := filepath.Abs(os.Args[0])
	if err != nil {
		return err
	}
	rule := winfw.FWRule{
		Name:            "sing-tun (" + absPath + ")",
		ApplicationName: absPath,
		Enabled:         true,
		Protocol:        winfw.NET_FW_IP_PROTOCOL_TCP,
		Direction:       winfw.NET_FW_RULE_DIR_IN,
		Action:          winfw.NET_FW_ACTION_ALLOW,
	}
	_, err = winfw.FirewallRuleAddAdvanced(rule)
	return err
}

func retryableListenError(err error) bool {
	return errors.Is(err, windows.WSAEADDRNOTAVAIL)
}
