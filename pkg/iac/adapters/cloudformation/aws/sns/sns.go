package sns

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/sns"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts a SNS instance
func Adapt(cfFile parser.FileContext) sns.SNS {
	return sns.SNS{
		Topics: getTopics(cfFile),
	}
}
