package digitalocean

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/digitalocean/compute"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/digitalocean/spaces"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/digitalocean"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) digitalocean.DigitalOcean {
	return digitalocean.DigitalOcean{
		Compute: compute.Adapt(modules),
		Spaces:  spaces.Adapt(modules),
	}
}
