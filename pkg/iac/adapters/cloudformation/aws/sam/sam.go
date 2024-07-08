package sam

import (
	"github.com/deepfactor-io/trivy/pkg/iac/providers/aws/sam"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an SAM instance
func Adapt(cfFile parser.FileContext) sam.SAM {
	return sam.SAM{
		APIs:          getApis(cfFile),
		HttpAPIs:      getHttpApis(cfFile),
		Functions:     getFunctions(cfFile),
		StateMachines: getStateMachines(cfFile),
		SimpleTables:  getSimpleTables(cfFile),
	}
}
