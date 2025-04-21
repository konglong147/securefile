package route

import (
	"net/netip"
	"strings"

	"github.com/konglong147/securefile/adapter"
	N "github.com/konglong147/securefile/local/sing/common/network"
)

var _ RuleItem = (*MeisozeDizhiTMes)(nil)

type MeisozeDizhiTMes struct {
	router   adapter.Router
	isSource bool
	codes    []string
	codeMap  map[string]bool
}

func NewMeisozeDizhiTMes(router adapter.Router,isSource bool, codes []string) *MeisozeDizhiTMes {
	codeMap := make(map[string]bool)
	for _, code := range codes {
		codeMap[code] = true
	}
	return &MeisozeDizhiTMes{
		router:   router,
		codes:    codes,
		isSource: isSource,
		codeMap:  codeMap,
	}
}

func (r *MeisozeDizhiTMes) Match(metadata *adapter.InboundContext) bool {
	var geoipCode string
	if r.isSource && metadata.SourceGeoIPCode != "" {
		geoipCode = metadata.SourceGeoIPCode
	} else if !r.isSource && metadata.GeoIPCode != "" {
		geoipCode = metadata.GeoIPCode
	}
	if geoipCode != "" {
		return r.codeMap[geoipCode]
	}
	var destination netip.Addr
	if r.isSource {
		destination = metadata.Source.Addr
	} else {
		destination = metadata.Destination.Addr
	}
	if destination.IsValid() {
		return r.match(metadata, destination)
	}
	for _, destinationAddress := range metadata.DestinationAddresses {
		if r.match(metadata, destinationAddress) {
			return true
		}
	}
	return false
}

func (r *MeisozeDizhiTMes) match(metadata *adapter.InboundContext, destination netip.Addr) bool {
	var geoipCode string
	geoReader := r.router.GeoIPReader()
	if !N.IsPublicAddr(destination) {
		geoipCode = "private"
	} else if geoReader != nil {
		geoipCode = geoReader.Lookup(destination)
	}
	if geoipCode == "" {
		return false
	}
	if r.isSource {
		metadata.SourceGeoIPCode = geoipCode
	} else {
		metadata.GeoIPCode = geoipCode
	}
	return r.codeMap[geoipCode]
}

func (r *MeisozeDizhiTMes) String() string {
	var description string
	if r.isSource {
		description = "source_geoip="
	} else {
		description = "geoip="
	}
	cLen := len(r.codes)
	if cLen == 1 {
		description += r.codes[0]
	} else if cLen > 3 {
		description += "[" + strings.Join(r.codes[:3], " ") + "...]"
	} else {
		description += "[" + strings.Join(r.codes, " ") + "]"
	}
	return description
}
