//go:build wireinject
// +build wireinject

package server

import (
<<<<<<< HEAD
	"github.com/deepfactor-io/trivy/pkg/fanal/cache"
=======
>>>>>>> fd5cafb26dfebcea6939572098650f79bafb430c
	"github.com/google/wire"

	"github.com/aquasecurity/trivy/pkg/fanal/cache"
)

func initializeScanServer(localArtifactCache cache.Cache) *ScanServer {
	wire.Build(ScanSuperSet)
	return &ScanServer{}
}
