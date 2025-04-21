package mux

import (
	"context"
	"net"

	"github.com/konglong147/securefile/adapter"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/local/sing-mux"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	"github.com/konglong147/securefile/local/sing/common/logger"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"
)

type Client = mux.Client

func NewClientWithOptions(dialer N.Dialer, logger logger.Logger, yousuocanshu option.OutboundMultiplexOptions) (*Client, error) {
	if !yousuocanshu.Enabled {
		return nil, nil
	}
	var brutalOptions mux.BrutalOptions
	if yousuocanshu.Brutal != nil && yousuocanshu.Brutal.Enabled {
		brutalOptions = mux.BrutalOptions{
			Enabled:    true,
			SendBPS:    uint64(yousuocanshu.Brutal.UpMbps * C.MbpsToBps),
			ReceiveBPS: uint64(yousuocanshu.Brutal.DownMbps * C.MbpsToBps),
		}
		if brutalOptions.SendBPS < mux.BrutalMinSpeedBPS {
			return nil, E.New("brutal: invalid upload speed")
		}
		if brutalOptions.ReceiveBPS < mux.BrutalMinSpeedBPS {
			return nil, E.New("brutal: invalid download speed")
		}
	}
	return mux.NewClient(mux.Options{
		Dialer:         &clientDialer{dialer},
		Logger:         logger,
		Protocol:       yousuocanshu.Protocol,
		MaxConnections: yousuocanshu.MaxConnections,
		MinStreams:     yousuocanshu.MinStreams,
		MaxStreams:     yousuocanshu.MaxStreams,
		Padding:        yousuocanshu.Padding,
		Brutal:         brutalOptions,
	})
}

type clientDialer struct {
	N.Dialer
}

func (d *clientDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.Dialer.DialContext(adapter.OverrideContext(ctx), network, destination)
}

func (d *clientDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.Dialer.ListenPacket(adapter.OverrideContext(ctx), destination)
}
