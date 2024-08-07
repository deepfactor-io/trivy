package compute

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type Network struct {
	Metadata    types.Metadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}
