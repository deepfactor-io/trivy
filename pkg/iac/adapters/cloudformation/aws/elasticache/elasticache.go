package elasticache

import (
	"github.com/deepfactor-io/trivy/pkg/iac/providers/aws/elasticache"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an ElasticCache instance
func Adapt(cfFile parser.FileContext) elasticache.ElastiCache {
	return elasticache.ElastiCache{
		Clusters:          getClusterGroups(cfFile),
		ReplicationGroups: getReplicationGroups(cfFile),
		SecurityGroups:    getSecurityGroups(cfFile),
	}
}
