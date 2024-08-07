package athena

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/athena"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an Athena instance
func Adapt(cfFile parser.FileContext) athena.Athena {
	return athena.Athena{
		Databases:  nil,
		Workgroups: getWorkGroups(cfFile),
	}
}
