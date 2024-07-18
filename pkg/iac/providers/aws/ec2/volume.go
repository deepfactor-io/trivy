package ec2

import (
	iacTypes "github.com/deepfactor-io/trivy/pkg/iac/types"
)

type Volume struct {
	Metadata   iacTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
	KMSKeyID iacTypes.StringValue
}
