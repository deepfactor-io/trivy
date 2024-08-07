package network

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type LoadBalancer struct {
	Metadata  iacTypes.Metadata
	Listeners []LoadBalancerListener
}

type LoadBalancerListener struct {
	Metadata  iacTypes.Metadata
	Protocol  iacTypes.StringValue
	TLSPolicy iacTypes.StringValue
}
