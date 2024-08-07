package ec2

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type Subnet struct {
	Metadata            iacTypes.Metadata
	MapPublicIpOnLaunch iacTypes.BoolValue
}
