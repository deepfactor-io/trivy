package types

import (
	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/sbom/core"
)

type SBOMSource = string

type SBOM struct {
	Metadata Metadata

	Packages     []ftypes.PackageInfo
	Applications []ftypes.Application

	BOM *core.BOM
}

const (
	SBOMSourceOCI   = SBOMSource("oci")
	SBOMSourceRekor = SBOMSource("rekor")
)

var (
	SBOMSources = []string{
		SBOMSourceOCI,
		SBOMSourceRekor,
	}
)
