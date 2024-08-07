package efs

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/efs"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

func getFileSystems(ctx parser.FileContext) (filesystems []efs.FileSystem) {

	filesystemResources := ctx.GetResourcesByType("AWS::EFS::FileSystem")

	for _, r := range filesystemResources {

		filesystem := efs.FileSystem{
			Metadata:  r.Metadata(),
			Encrypted: r.GetBoolProperty("Encrypted"),
		}

		filesystems = append(filesystems, filesystem)
	}

	return filesystems
}
