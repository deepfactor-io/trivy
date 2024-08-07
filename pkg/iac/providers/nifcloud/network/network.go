package network

import iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"

type Network struct {
	ElasticLoadBalancers []ElasticLoadBalancer
	LoadBalancers        []LoadBalancer
	Routers              []Router
	VpnGateways          []VpnGateway
}

type NetworkInterface struct {
	Metadata     iacTypes.Metadata
	NetworkID    iacTypes.StringValue
	IsVipNetwork iacTypes.BoolValue
}
