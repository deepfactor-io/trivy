package cloudformation

import (
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/cloudformation/aws"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/deepfactor-io/trivy/pkg/iac/state"
)

// Adapt adapts the Cloudformation instance
func Adapt(cfFile parser.FileContext) *state.State {
	return &state.State{
		AWS: aws.Adapt(cfFile),
	}
}
