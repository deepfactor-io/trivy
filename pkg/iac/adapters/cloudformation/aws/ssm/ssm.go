package ssm

import (
	"github.com/deepfactor-io/trivy/pkg/iac/providers/aws/ssm"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an SSM instance
func Adapt(cfFile parser.FileContext) ssm.SSM {
	return ssm.SSM{
		Secrets: getSecrets(cfFile),
	}
}
