package version

import (
	"strings"
	"time"

	"k8s.io/utils/clock"

	ftypes "github.com/deepfactor-io/trivy/v3/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/v3/pkg/log"
)

// Major returns the major version
// e.g. 8.1 => 8
func Major(osVer string) string {
	osVer, _, _ = strings.Cut(osVer, ".")
	return osVer
}

// Minor returns the major and minor version
// e.g. 3.17.2 => 3.17
func Minor(osVer string) string {
	major, s, ok := strings.Cut(osVer, ".")
	if !ok {
		return osVer
	}
	minor, _, _ := strings.Cut(s, ".")
	return major + "." + minor
}

func Supported(c clock.Clock, eolDates map[string]time.Time, osFamily ftypes.OSType, osVer string) bool {
	eol, ok := eolDates[osVer]
	if !ok {
		log.Logger.Warnf("This OS version is not on the EOL list: %s %s", osFamily, osVer)
		return true // can be the latest version
	}
	return c.Now().Before(eol)
}
