//go:build wireinject
// +build wireinject

package server

import (
	"github.com/deepfactor-io/trivy/pkg/fanal/cache"
	"github.com/google/wire"
)

func initializeScanServer(localArtifactCache cache.LocalArtifactCache) *ScanServer {
	wire.Build(ScanSuperSet)
	return &ScanServer{}
}
