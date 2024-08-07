package nas

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type NASInstance struct {
	Metadata  iacTypes.Metadata
	NetworkID iacTypes.StringValue
}
