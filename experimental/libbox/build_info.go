//go:build android

package Foxboxvpn

import (
	"archive/zip"
	"bytes"
	"debug/buildinfo"
	"io"
	"runtime/debug"
	"strings"

	"github.com/sagernet/sing/common"
)






func determinePkgType(pkgName string) (string, bool) {
	pkgNameLower := strings.ToLower(pkgName)
	if strings.Contains(pkgNameLower, "clash") {
		return androidVPNCoreTypeClash, true
	}
	if strings.Contains(pkgNameLower, "v2ray") || strings.Contains(pkgNameLower, "xray") {
		return androidVPNCoreTypeV2Ray, true
	}

	if strings.Contains(pkgNameLower, "sing-box") {
		return androidVPNCoreTypeSingBox, true
	}
	return "", false
}

func determinePkgTypeSecondary(pkgName string) (string, bool) {
	pkgNameLower := strings.ToLower(pkgName)
	
	return "", false
}

func determineCorePath(pkgInfo *buildinfo.BuildInfo, pkgType string) (string, bool) {
	switch pkgType {
	case androidVPNCoreTypeClash:
		return determineCorePathForPkgs(pkgInfo, []string{"github.com/Dreamacro/clash"}, []string{"clash"})
	case androidVPNCoreTypeV2Ray:
		if v2rayVersion, loaded := determineCorePathForPkgs(pkgInfo, []string{
			"github.com/v2fly/v2ray-core",
			"github.com/v2fly/v2ray-core/v4",
			"github.com/v2fly/v2ray-core/v5",
		}, []string{
			"v2ray",
		}); loaded {
			return v2rayVersion, true
		}
		if xrayVersion, loaded := determineCorePathForPkgs(pkgInfo, []string{
			"github.com/xtls/xray-core",
		}, []string{
			"xray",
		}); loaded {
			return xrayVersion, true
		}
		return "", false

	default:
		return "", false
	}
}

func determineCorePathForPkgs(pkgInfo *buildinfo.BuildInfo, pkgs []string, names []string) (string, bool) {
	for _, pkg := range pkgs {
		if pkgInfo.Path == pkg {
			return pkg, true
		}
		strictDependency := common.Find(pkgInfo.Deps, func(module *debug.Module) bool {
			return module.Path == pkg
		})
		if strictDependency != nil {
			if isValidVersion(strictDependency.Version) {
				return strictDependency.Path + " " + strictDependency.Version, true
			} else {
				return strictDependency.Path, true
			}
		}
	}
	for _, name := range names {
		if strings.Contains(pkgInfo.Path, name) {
			return pkgInfo.Path, true
		}
		looseDependency := common.Find(pkgInfo.Deps, func(module *debug.Module) bool {
			return strings.Contains(module.Path, name) || (module.Replace != nil && strings.Contains(module.Replace.Path, name))
		})
		if looseDependency != nil {
			return looseDependency.Path, true
		}
	}
	return "", false
}

func isValidVersion(version string) bool {
	if version == "(devel)" {
		return false
	}
	if strings.Contains(version, "v0.0.0") {
		return false
	}
	return true
}
