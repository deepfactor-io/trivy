package cloudwatch

import (
	"github.com/deepfactor-io/trivy/pkg/iac/providers/aws/cloudwatch"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts a Cloudwatch instance
func Adapt(cfFile parser.FileContext) cloudwatch.CloudWatch {
	return cloudwatch.CloudWatch{
		LogGroups: getLogGroups(cfFile),
	}
}
