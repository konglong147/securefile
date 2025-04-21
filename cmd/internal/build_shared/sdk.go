package build_shared

import (
	"go/build"
	"path/filepath"
)

var GoBinPath string

func FindMobile() {
	goBin := filepath.Join(build.Default.GOPATH, "bin")
	GoBinPath = goBin
}
