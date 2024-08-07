package ssm

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type SSM struct {
	Secrets []Secret
}

type Secret struct {
	Metadata iacTypes.Metadata
	KMSKeyID iacTypes.StringValue
}

const DefaultKMSKeyID = "alias/aws/secretsmanager"
