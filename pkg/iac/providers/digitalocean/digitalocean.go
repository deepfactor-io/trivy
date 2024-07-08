package digitalocean

import (
	"github.com/deepfactor-io/trivy/pkg/iac/providers/digitalocean/compute"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/digitalocean/spaces"
)

type DigitalOcean struct {
	Compute compute.Compute
	Spaces  spaces.Spaces
}
