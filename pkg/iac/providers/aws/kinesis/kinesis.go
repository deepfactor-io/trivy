package kinesis

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type Kinesis struct {
	Streams []Stream
}

type Stream struct {
	Metadata   iacTypes.Metadata
	Encryption Encryption
}

const (
	EncryptionTypeKMS = "KMS"
)

type Encryption struct {
	Metadata iacTypes.Metadata
	Type     iacTypes.StringValue
	KMSKeyID iacTypes.StringValue
}
