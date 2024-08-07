package sqs

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/iam"
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type SQS struct {
	Queues []Queue
}

type Queue struct {
	Metadata   iacTypes.Metadata
	QueueURL   iacTypes.StringValue
	Encryption Encryption
	Policies   []iam.Policy
}

type Encryption struct {
	Metadata          iacTypes.Metadata
	KMSKeyID          iacTypes.StringValue
	ManagedEncryption iacTypes.BoolValue
}
