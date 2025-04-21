package platform

import (
	"github.com/konglong147/securefile/common/process"
	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/local/sing-tun"
)
// TempfoxvSecureTemp
type LuowangLian interface {
	// TempfoxvSecureTemp
	KaiDaZheZhuanWithD(yousuocanshu *tun.Options, platformOptions option.TaipingForShuju) (tun.Tun, error)
	// TempfoxvSecureTemp
	ZhanHuoWanLeXia() bool
	// TempfoxvSecureTemp
	LuoWangHanYouSuo() bool
	// TempfoxvSecureTemp
	process.Searcher
}

