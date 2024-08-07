package redshift

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/redshift"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

func getSecurityGroups(ctx parser.FileContext) (groups []redshift.SecurityGroup) {
	for _, groupResource := range ctx.GetResourcesByType("AWS::Redshift::ClusterSecurityGroup") {
		group := redshift.SecurityGroup{
			Metadata:    groupResource.Metadata(),
			Description: groupResource.GetProperty("Description").AsStringValue(),
		}
		groups = append(groups, group)
	}
	return groups
}
