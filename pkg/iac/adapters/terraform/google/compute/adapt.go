package compute

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/google/compute"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) compute.Compute {
	return compute.Compute{
		ProjectMetadata: adaptProjectMetadata(modules),
		Instances:       adaptInstances(modules),
		Disks:           adaptDisks(modules),
		Networks:        adaptNetworks(modules),
		SSLPolicies:     adaptSSLPolicies(modules),
	}
}
