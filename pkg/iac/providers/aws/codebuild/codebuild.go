package codebuild

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type CodeBuild struct {
	Projects []Project
}

type Project struct {
	Metadata                  iacTypes.Metadata
	ArtifactSettings          ArtifactSettings
	SecondaryArtifactSettings []ArtifactSettings
}

type ArtifactSettings struct {
	Metadata          iacTypes.Metadata
	EncryptionEnabled iacTypes.BoolValue
}
