package efs

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/efs"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an EFS instance
func Adapt(cfFile parser.FileContext) efs.EFS {
	return efs.EFS{
		FileSystems: getFileSystems(cfFile),
	}
}
