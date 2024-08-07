package ecr

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/ecr"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an ECR instance
func Adapt(cfFile parser.FileContext) ecr.ECR {
	return ecr.ECR{
		Repositories: getRepositories(cfFile),
	}
}
