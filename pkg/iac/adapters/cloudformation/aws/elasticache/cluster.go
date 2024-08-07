package elasticache

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/elasticache"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

func getClusterGroups(ctx parser.FileContext) (clusters []elasticache.Cluster) {

	clusterResources := ctx.GetResourcesByType("AWS::ElastiCache::CacheCluster")

	for _, r := range clusterResources {
		cluster := elasticache.Cluster{
			Metadata:               r.Metadata(),
			Engine:                 r.GetStringProperty("Engine"),
			NodeType:               r.GetStringProperty("CacheNodeType"),
			SnapshotRetentionLimit: r.GetIntProperty("SnapshotRetentionLimit"),
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}
