package cloudstack

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/cloudstack/compute"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/cloudstack"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) cloudstack.CloudStack {
	return cloudstack.CloudStack{
		Compute: compute.Adapt(modules),
	}
}
