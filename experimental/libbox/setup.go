package Foxboxvpn

import (
	"os"
	"os/user"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/konglong147/securefile/common/humanize"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/experimental/locale"
	_ "github.com/konglong147/securefile/include"
	"github.com/konglong147/securefile/log"
)

var (
	sBasePath    string
	sWorkingPath string
	sTempPath    string
	sUserID      int
	sGroupID     int
	sTVOS        bool
)

func init() {
	debug.SetPanicOnFault(true)
}

func Setup(basePath string, workingPath string, tempPath string, isTVOS bool) {
	sBasePath = basePath
	sWorkingPath = workingPath
	sTempPath = tempPath
	sUserID = os.Getuid()
	sGroupID = os.Getgid()
	sTVOS = isTVOS
	os.MkdirAll(sWorkingPath, 0o777)
	os.MkdirAll(sTempPath, 0o777)
}

func SetupWithUsername(basePath string, workingPath string, tempPath string, username string) error {
	sBasePath = basePath
	sWorkingPath = workingPath
	sTempPath = tempPath
	sUser, err := user.Lookup(username)
	if err != nil {
		return err
	}
	sUserID, _ = strconv.Atoi(sUser.Uid)
	sGroupID, _ = strconv.Atoi(sUser.Gid)
	os.MkdirAll(sWorkingPath, 0o777)
	os.MkdirAll(sTempPath, 0o777)
	os.Chown(sWorkingPath, sUserID, sGroupID)
	os.Chown(sTempPath, sUserID, sGroupID)
	return nil
}

func SetLocale(localeId string) {
	locale.Set(localeId)
}

func Version() string {
	return C.Version
}

func FormatBytes(length int64) string {
	return humanize.Bytes(uint64(length))
}

func FormatMemoryBytes(length int64) string {
	return humanize.MemoryBytes(uint64(length))
}

func FormatDuration(duration int64) string {
	return log.FormatDuration(time.Duration(duration) * time.Millisecond)
}

func ProxyDisplayType(proxyType string) string {
	return C.ProxyDisplayName(proxyType)
}
