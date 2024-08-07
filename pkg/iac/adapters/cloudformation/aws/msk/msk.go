package msk

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/msk"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an MSK instance
func Adapt(cfFile parser.FileContext) msk.MSK {
	return msk.MSK{
		Clusters: getClusters(cfFile),
	}
}
