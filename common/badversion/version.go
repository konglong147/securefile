package badversion

import (
	"strconv"
	"strings"

	F "github.com/konglong147/securefile/local/sing/common/format"
)

type Version struct {
	Major                int
	Minor                int
	Patch                int
	Commit               string
	PreReleaseIdentifier string
	PreReleaseVersion    int
}

func (v Version) After(anotherVersion Version) bool {
	if v.Major > anotherVersion.Major {
		return true
	} else if v.Major < anotherVersion.Major {
		return false
	}
	if v.Minor > anotherVersion.Minor {
		return true
	} else if v.Minor < anotherVersion.Minor {
		return false
	}
	if v.Patch > anotherVersion.Patch {
		return true
	} else if v.Patch < anotherVersion.Patch {
		return false
	}
	if v.PreReleaseIdentifier == "" && anotherVersion.PreReleaseIdentifier != "" {
		return true
	} else if v.PreReleaseIdentifier != "" && anotherVersion.PreReleaseIdentifier == "" {
		return false
	}
	if v.PreReleaseIdentifier != "" && anotherVersion.PreReleaseIdentifier != "" {
		if v.PreReleaseIdentifier == anotherVersion.PreReleaseIdentifier {
			if v.PreReleaseVersion > anotherVersion.PreReleaseVersion {
				return true
			} else if v.PreReleaseVersion < anotherVersion.PreReleaseVersion {
				return false
			}
		} else if v.PreReleaseIdentifier == "rc" && anotherVersion.PreReleaseIdentifier == "beta" {
			return true
		} else if v.PreReleaseIdentifier == "beta" && anotherVersion.PreReleaseIdentifier == "rc" {
			return false
		} else if v.PreReleaseIdentifier == "beta" && anotherVersion.PreReleaseIdentifier == "alpha" {
			return true
		} else if v.PreReleaseIdentifier == "alpha" && anotherVersion.PreReleaseIdentifier == "beta" {
			return false
		}
	}
	return false
}

func (v Version) VersionString() string {
	return F.ToString(v.Major, ".", v.Minor, ".", v.Patch)
}

func (v Version) String() string {
	version := F.ToString(v.Major, ".", v.Minor, ".", v.Patch)
	if v.PreReleaseIdentifier != "" {
		version = F.ToString(version, "-", v.PreReleaseIdentifier, ".", v.PreReleaseVersion)
	}
	return version
}

func (v Version) BadString() string {
	version := F.ToString(v.Major, ".", v.Minor)
	if v.Patch > 0 {
		version = F.ToString(version, ".", v.Patch)
	}
	if v.PreReleaseIdentifier != "" {
		version = F.ToString(version, "-", v.PreReleaseIdentifier)
		if v.PreReleaseVersion > 0 {
			version = F.ToString(version, v.PreReleaseVersion)
		}
	}
	return version
}

func Parse(versionName string) (version Version) {
	if strings.HasPrefix(versionName, "v") {
		versionName = versionName[1:]
	}
	if strings.Contains(versionName, "-") {
		parts := strings.Split(versionName, "-")
		versionName = parts[0]
		identifier := parts[1]
		if strings.Contains(identifier, ".") {
			identifierParts := strings.Split(identifier, ".")
			version.PreReleaseIdentifier = identifierParts[0]
			if len(identifierParts) >= 2 {
				version.PreReleaseVersion, _ = strconv.Atoi(identifierParts[1])
			}
		} else {
			if strings.HasPrefix(identifier, "alpha") {
				version.PreReleaseIdentifier = "alpha"
				version.PreReleaseVersion, _ = strconv.Atoi(identifier[5:])
			} else if strings.HasPrefix(identifier, "beta") {
				version.PreReleaseIdentifier = "beta"
				version.PreReleaseVersion, _ = strconv.Atoi(identifier[4:])
			} else {
				version.Commit = identifier
			}
		}
	}
	versionElements := strings.Split(versionName, ".")
	versionLen := len(versionElements)
	if versionLen >= 1 {
		version.Major, _ = strconv.Atoi(versionElements[0])
	}
	if versionLen >= 2 {
		version.Minor, _ = strconv.Atoi(versionElements[1])
	}
	if versionLen >= 3 {
		version.Patch, _ = strconv.Atoi(versionElements[2])
	}
	return
}
