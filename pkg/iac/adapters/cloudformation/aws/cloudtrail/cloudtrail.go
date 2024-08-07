package cloudtrail

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/cloudtrail"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts a CloudTrail instance
func Adapt(cfFile parser.FileContext) cloudtrail.CloudTrail {
	return cloudtrail.CloudTrail{
		Trails: getCloudTrails(cfFile),
	}
}
