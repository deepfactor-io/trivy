package codebuild

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/codebuild"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts a CodeBuild instance
func Adapt(cfFile parser.FileContext) codebuild.CodeBuild {
	return codebuild.CodeBuild{
		Projects: getProjects(cfFile),
	}
}
