package ecs

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/ecs"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an ECS instance
func Adapt(cfFile parser.FileContext) ecs.ECS {
	return ecs.ECS{
		Clusters:        getClusters(cfFile),
		TaskDefinitions: getTaskDefinitions(cfFile),
	}
}
