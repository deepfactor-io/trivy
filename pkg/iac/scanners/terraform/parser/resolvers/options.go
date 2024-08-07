package resolvers

import (
	"strings"

	"github.com/deepfactor-io/trivy/v3/pkg/iac/debug"
)

type Options struct {
	Source, OriginalSource, Version, OriginalVersion, WorkingDir, Name, ModulePath string
	DebugLogger                                                                    debug.Logger
	AllowDownloads                                                                 bool
	SkipCache                                                                      bool
	RelativePath                                                                   string
	CacheDir                                                                       string
}

func (o *Options) hasPrefix(prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(o.Source, prefix) {
			return true
		}
	}
	return false
}

func (o *Options) Debug(format string, args ...any) {
	o.DebugLogger.Log(format, args...)
}
