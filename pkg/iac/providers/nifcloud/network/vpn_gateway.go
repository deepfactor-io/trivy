package network

import (
	iacTypes "github.com/deepfactor-io/trivy/pkg/iac/types"
)

type VpnGateway struct {
	Metadata      iacTypes.Metadata
	SecurityGroup iacTypes.StringValue
}
