package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	_ "github.com/sagernet/gomobile"
	"github.com/konglong147/securefile/cmd/internal/build_shared"
	"github.com/konglong147/securefile/local/sing/common/rw"
)

var (
	debugEnabled bool
	target       string
	platform     string
)

func init() {
	flag.BoolVar(&debugEnabled, "debug", false, "enable debug")
	flag.StringVar(&target, "target", "", "target platform")
	flag.StringVar(&platform, "platform", "", "specify platform")
}

func main() {
	flag.Parse()

	build_shared.FindMobile()

	switch target {
	case "apple":
		buildApple()
	}
}

var (
	sharedFlags []string
	debugFlags  []string
	sharedTags  []string
	iosTags     []string
	debugTags   []string
)

func init() {
	sharedFlags = append(sharedFlags, "-trimpath")
	sharedFlags = append(sharedFlags, "-buildvcs=false")
	currentTag, err := build_shared.ReadTag()
	if err != nil {
		currentTag = "unknown"
	}
	sharedFlags = append(sharedFlags, "-ldflags", "-X github.com/konglong147/securefile/constant.Version="+currentTag+" -s -w -buildid=")
	debugFlags = append(debugFlags, "-ldflags", "-X github.com/konglong147/securefile/constant.Version="+currentTag)

	sharedTags = append(sharedTags, "with_gvisor", "with_quic", "", "with_ech", "with_utls", "with_clash_api")
	iosTags = append(iosTags, "with_dhcp", "with_low_memory", "with_conntrack")
	debugTags = append(debugTags, "debug")
}



func buildApple() {
	var bindTarget string
	if platform != "" {
		bindTarget = platform
	} else if debugEnabled {
		bindTarget = "ios"
	} else {
		bindTarget = "ios"
	}

	args := []string{
		"bind",
		"-v",
		"-target", bindTarget,
		"-libname=box",
	}
	if !debugEnabled {
		args = append(args, sharedFlags...)
	} else {
		args = append(args, debugFlags...)
	}

	tags := append(sharedTags, iosTags...)
	args = append(args, "-tags")
	if !debugEnabled {
		args = append(args, strings.Join(tags, ","))
	} else {
		args = append(args, strings.Join(append(tags, debugTags...), ","))
	}
	args = append(args, "./experimental/libbox")

	command := exec.Command(build_shared.GoBinPath+"/gomobile", args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
	}

	copyPath := filepath.Join("..", "sing-box-for-apple")
	if rw.IsDir(copyPath) {
		targetDir := filepath.Join(copyPath, "HuSecure.xcframework")
		targetDir, _ = filepath.Abs(targetDir)
		os.RemoveAll(targetDir)
		os.Rename("HuSecure.xcframework", targetDir)
	}
}
