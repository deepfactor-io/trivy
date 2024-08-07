package digitalocean

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/digitalocean/compute"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/digitalocean/spaces"
)

type DigitalOcean struct {
	Compute compute.Compute
	Spaces  spaces.Spaces
}
