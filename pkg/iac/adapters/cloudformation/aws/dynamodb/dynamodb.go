package dynamodb

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/dynamodb"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts a dynamodb instance
func Adapt(cfFile parser.FileContext) dynamodb.DynamoDB {
	return dynamodb.DynamoDB{
		DAXClusters: getClusters(cfFile),
	}
}
