package box

import (
	"strings"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/common/taskmonitor"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/local/sing/common"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	F "github.com/konglong147/securefile/local/sing/common/format"
)

func (s *Longxiang) shiKaiWaibose() error {
	themissaaer := taskmonitor.New(C.StartTimeout)
	waibossages := make(map[adapter.Outbound]string)
	waimianshujuku := make(map[string]adapter.Outbound)
	for i, waioussoutukais := range s.waimianshujuku {
		var waiouttgase string
		if waioussoutukais.Tag() == "" {
			waiouttgase = F.ToString(i)
		} else {
			waiouttgase = waioussoutukais.Tag()
		}
		if _, exists := waimianshujuku[waiouttgase]; exists {
			return E.New("outbound tag ", waiouttgase, " duplicated")
		}
		waibossages[waioussoutukais] = waiouttgase
		waimianshujuku[waiouttgase] = waioussoutukais
	}
	kaisitaed := make(map[string]bool)
	for {
		canContinue := false
	startOne:
		for _, waioussoutukais := range s.waimianshujuku {
			waiouttgase := waibossages[waioussoutukais]
			if kaisitaed[waiouttgase] {
				continue
			}
			dependencies := waioussoutukais.Dependencies()
			for _, dependency := range dependencies {
				if !kaisitaed[dependency] {
					continue startOne
				}
			}
			kaisitaed[waiouttgase] = true
			canContinue = true
			if starter, isStarter := waioussoutukais.(interface {
				Start() error
			}); isStarter {
				themissaaer.Start("initialize outbound/", waioussoutukais.Type(), "[", waiouttgase, "]")
				err := starter.Start()
				themissaaer.Finish()
				if err != nil {
					return E.Cause(err, "initialize outbound/", waioussoutukais.Type(), "[", waiouttgase, "]")
				}
			}
		}
		if len(kaisitaed) == len(s.waimianshujuku) {
			break
		}
		if canContinue {
			continue
		}
		dangqianoutssees := common.Find(s.waimianshujuku, func(it adapter.Outbound) bool {
			return !kaisitaed[waibossages[it]]
		})
		var lintOutbound func(oTree []string, oCurrent adapter.Outbound) error
		lintOutbound = func(oTree []string, oCurrent adapter.Outbound) error {
			wentiwaibotgaes := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !kaisitaed[it]
			})
			if common.Contains(oTree, wentiwaibotgaes) {
				return E.New("circular outbound dependency: ", strings.Join(oTree, " -> "), " -> ", wentiwaibotgaes)
			}
			problemOutbound := waimianshujuku[wentiwaibotgaes]
			if problemOutbound == nil {
				return E.New("dependency[", wentiwaibotgaes, "] not found for outbound[", waibossages[oCurrent], "]")
			}
			return lintOutbound(append(oTree, wentiwaibotgaes), problemOutbound)
		}
		return lintOutbound([]string{waibossages[dangqianoutssees]}, dangqianoutssees)
	}
	return nil
}
