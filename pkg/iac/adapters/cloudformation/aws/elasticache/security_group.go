package elasticache

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/elasticache"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

func getSecurityGroups(ctx parser.FileContext) (securityGroups []elasticache.SecurityGroup) {

	sgResources := ctx.GetResourcesByType("AWS::ElastiCache::SecurityGroup")

	for _, r := range sgResources {

		sg := elasticache.SecurityGroup{
			Metadata:    r.Metadata(),
			Description: r.GetStringProperty("Description"),
		}
		securityGroups = append(securityGroups, sg)
	}

	return securityGroups
}
