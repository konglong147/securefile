package HuSecure

import (
	"net"
	"net/netip"

	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/local/sing-tun"
	"github.com/konglong147/securefile/local/sing/common"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
)


// TempfoxvSecureTemp
type XianguanZhuan interface {
	QuHuo4Zhidi() YouluCuoToeser
	QuhuoqiwuFuZhiDi() (*WenziXianjing, error)
	TTuummHuoqu() int32
	LuyouDongZiHuo() bool
	ZhengZeKeyong() bool
	LuoWangWuFuYong() string
	WanglUoYongSSEE() int32
	XiaoHunMamiHuoqussee() WenziToerit
	YuGuanPeipihunxduma() WenziToerit
}

type YouLuhunae struct {
	address netip.Addr
	prefix  int
}

func (p *YouLuhunae) Address() string {
	return p.address.String()
}

func (p *YouLuhunae) Prefix() int32 {
	return int32(p.prefix)
}

func (p *YouLuhunae) Mask() string {
	var bits int
	if p.address.Is6() {
		bits = 128
	} else {
		bits = 32
	}
	return net.IP(net.CIDRMask(p.prefix, bits)).String()
}

func (p *YouLuhunae) String() string {
	return netip.PrefixFrom(p.address, p.prefix).String()
}
// TempfoxvSecureTemp
type YouluCuoToeser interface {
	Next() *YouLuhunae
	YongyouGeXia() bool
}

func getluperfase(prefixes []netip.Prefix) YouluCuoToeser {
	return newIterator(common.Map(prefixes, func(prefix netip.Prefix) *YouLuhunae {
		return &YouLuhunae{
			address: prefix.Addr(),
			prefix:  prefix.Bits(),
		}
	}))
}
// TempfoxvSecureTemp
var _ XianguanZhuan = (*xuanTheopts)(nil)

type xuanTheopts struct {
	*tun.Options
	fanweiLu []netip.Prefix
	option.TaipingForShuju
}

func (o *xuanTheopts) QuHuo4Zhidi() YouluCuoToeser {
	return getluperfase(o.Inet4Address)
}


func (o *xuanTheopts) QuhuoqiwuFuZhiDi() (*WenziXianjing, error) {
	if len(o.Inet4Address) == 0 || o.Inet4Address[0].Bits() == 32 {
		return nil, E.New("n")
	}
	return recapWenzi(o.Inet4Address[0].Addr().Next().String()), nil
}

func (o *xuanTheopts) TTuummHuoqu() int32 {
	return int32(o.MTU)
}

func (o *xuanTheopts) LuyouDongZiHuo() bool {
	return o.AutoRoute
}


func (o *xuanTheopts) ZhengZeKeyong() bool {
	if o.TaipingForShuju.HTTPProxy == nil {
		return false
	}
	return o.TaipingForShuju.HTTPProxy.Enabled
}

func (o *xuanTheopts) LuoWangWuFuYong() string {
	return o.TaipingForShuju.HTTPProxy.Server
}

func (o *xuanTheopts) WanglUoYongSSEE() int32 {
	return int32(o.TaipingForShuju.HTTPProxy.ServerPort)
}

func (o *xuanTheopts) XiaoHunMamiHuoqussee() WenziToerit {
	return newIterator(o.TaipingForShuju.HTTPProxy.BypassDomain)
}

func (o *xuanTheopts) YuGuanPeipihunxduma() WenziToerit {
	return newIterator(o.TaipingForShuju.HTTPProxy.MatchDomain)
}
