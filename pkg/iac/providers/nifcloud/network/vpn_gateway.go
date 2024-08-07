package network

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type VpnGateway struct {
	Metadata      iacTypes.Metadata
	SecurityGroup iacTypes.StringValue
}
