package eks

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/eks"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an EKS instance
func Adapt(cfFile parser.FileContext) eks.EKS {
	return eks.EKS{
		Clusters: getClusters(cfFile),
	}
}
