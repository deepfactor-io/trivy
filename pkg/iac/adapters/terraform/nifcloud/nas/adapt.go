package nas

import (
	"github.com/deepfactor-io/trivy/pkg/iac/providers/nifcloud/nas"
	"github.com/deepfactor-io/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) nas.NAS {
	return nas.NAS{
		NASSecurityGroups: adaptNASSecurityGroups(modules),
		NASInstances:      adaptNASInstances(modules),
	}
}
