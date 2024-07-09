//go:build wireinject
// +build wireinject

package server

import (
	"github.com/google/wire"

	"github.com/deepfactor-io/trivy/pkg/cache"
)

func initializeScanServer(localArtifactCache cache.LocalArtifactCache) *ScanServer {
	wire.Build(ScanSuperSet)
	return &ScanServer{}
}
