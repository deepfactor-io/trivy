package compute

import (
	iacTypes "github.com/deepfactor-io/trivy/pkg/iac/types"
)

type ProjectMetadata struct {
	Metadata      iacTypes.Metadata
	EnableOSLogin iacTypes.BoolValue
}
