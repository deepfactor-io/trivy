package efs

import (
	iacTypes "github.com/deepfactor-io/trivy/pkg/iac/types"
)

type EFS struct {
	FileSystems []FileSystem
}

type FileSystem struct {
	Metadata  iacTypes.Metadata
	Encrypted iacTypes.BoolValue
}
