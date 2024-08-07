package network

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/nifcloud/network"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) network.Network {

	return network.Network{
		ElasticLoadBalancers: adaptElasticLoadBalancers(modules),
		LoadBalancers:        adaptLoadBalancers(modules),
		Routers:              adaptRouters(modules),
		VpnGateways:          adaptVpnGateways(modules),
	}
}
