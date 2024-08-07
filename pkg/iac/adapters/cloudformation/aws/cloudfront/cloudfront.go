package cloudfront

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/cloudfront"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts a CloudFront instance
func Adapt(cfFile parser.FileContext) cloudfront.Cloudfront {
	return cloudfront.Cloudfront{
		Distributions: getDistributions(cfFile),
	}
}
