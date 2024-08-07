package efs

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type EFS struct {
	FileSystems []FileSystem
}

type FileSystem struct {
	Metadata  iacTypes.Metadata
	Encrypted iacTypes.BoolValue
}
