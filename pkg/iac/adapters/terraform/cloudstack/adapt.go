package cloudstack

import (
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/cloudstack/compute"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/cloudstack"
	"github.com/deepfactor-io/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) cloudstack.CloudStack {
	return cloudstack.CloudStack{
		Compute: compute.Adapt(modules),
	}
}
