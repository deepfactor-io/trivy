package ec2

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/ec2"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an EC2 instance
func Adapt(cfFile parser.FileContext) ec2.EC2 {
	return ec2.EC2{
		LaunchConfigurations: getLaunchConfigurations(cfFile),
		LaunchTemplates:      getLaunchTemplates(cfFile),
		Instances:            getInstances(cfFile),
		VPCs:                 nil,
		NetworkACLs:          getNetworkACLs(cfFile),
		SecurityGroups:       getSecurityGroups(cfFile),
		Subnets:              getSubnets(cfFile),
		Volumes:              getVolumes(cfFile),
	}
}
