package main

import (
	"context"
	"os"

	"github.com/konglong147/securefile/common/settings"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"

	"github.com/spf13/cobra"
)

var (
	commandSyncTimeFlagServer   string
	commandSyncTimeOutputFormat string
	commandSyncTimeWrite        bool
)

var commandSyncTime = &cobra.Command{
	Use:   "synctime",
	Short: "Sync time using the NTP protocol",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		err := syncTime()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandSyncTime.Flags().StringVarP(&commandSyncTimeFlagServer, "server", "s", "time.apple.com", "Set NTP server")
	commandSyncTime.Flags().StringVarP(&commandSyncTimeOutputFormat, "format", "f", C.TimeLayout, "Set output format")
	commandSyncTime.Flags().BoolVarP(&commandSyncTimeWrite, "write", "w", false, "Write time to system")
	commandTools.AddCommand(commandSyncTime)
}

func syncTime() error {
	instance, err := createPreStartedClient()
	if err != nil {
		return err
	}
	dialer, err := createDialer(instance, N.NetworkUDP, commandToolsFlagOutbound)
	if err != nil {
		return err
	}
	defer instance.Close()
	serverAddress := M.ParseSocksaddr(commandSyncTimeFlagServer)
	if serverAddress.Port == 0 {
		serverAddress.Port = 123
	}
	response, err := ntp.Exchange(context.Background(), dialer, serverAddress)
	if err != nil {
		return err
	}
	if commandSyncTimeWrite {
		err = settings.SetSystemTime(response.Time)
		if err != nil {
			return E.Cause(err, "write time to system")
		}
	}
	os.Stdout.WriteString(response.Time.Local().Format(commandSyncTimeOutputFormat))
	return nil
}
