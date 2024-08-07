package compute

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type ProjectMetadata struct {
	Metadata      iacTypes.Metadata
	EnableOSLogin iacTypes.BoolValue
}
