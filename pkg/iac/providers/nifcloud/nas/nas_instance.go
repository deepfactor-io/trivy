package nas

import (
	iacTypes "github.com/deepfactor-io/trivy/pkg/iac/types"
)

type NASInstance struct {
	Metadata  iacTypes.Metadata
	NetworkID iacTypes.StringValue
}
