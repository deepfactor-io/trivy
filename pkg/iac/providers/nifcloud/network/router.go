package network

import (
	iacTypes "github.com/deepfactor-io/trivy/pkg/iac/types"
)

type Router struct {
	Metadata          iacTypes.Metadata
	SecurityGroup     iacTypes.StringValue
	NetworkInterfaces []NetworkInterface
}
