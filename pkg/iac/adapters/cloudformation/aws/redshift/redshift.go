package redshift

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/redshift"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts a RedShift instance
func Adapt(cfFile parser.FileContext) redshift.Redshift {
	return redshift.Redshift{
		Clusters:          getClusters(cfFile),
		SecurityGroups:    getSecurityGroups(cfFile),
		ClusterParameters: getParameters(cfFile),
		ReservedNodes:     nil,
	}
}
