package compute

import (
	"github.com/deepfactor-io/trivy/pkg/iac/types"
)

type Network struct {
	Metadata    types.Metadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}
