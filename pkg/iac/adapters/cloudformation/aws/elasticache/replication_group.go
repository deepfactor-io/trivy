package elasticache

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/elasticache"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

func getReplicationGroups(ctx parser.FileContext) (replicationGroups []elasticache.ReplicationGroup) {

	replicationGroupResources := ctx.GetResourcesByType("AWS::ElastiCache::ReplicationGroup")

	for _, r := range replicationGroupResources {
		replicationGroup := elasticache.ReplicationGroup{
			Metadata:                 r.Metadata(),
			TransitEncryptionEnabled: r.GetBoolProperty("TransitEncryptionEnabled"),
			AtRestEncryptionEnabled:  r.GetBoolProperty("AtRestEncryptionEnabled"),
		}

		replicationGroups = append(replicationGroups, replicationGroup)
	}

	return replicationGroups
}
