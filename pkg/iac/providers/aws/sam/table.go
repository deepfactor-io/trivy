package sam

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type SimpleTable struct {
	Metadata         iacTypes.Metadata
	TableName        iacTypes.StringValue
	SSESpecification SSESpecification
}

type SSESpecification struct {
	Metadata iacTypes.Metadata

	Enabled        iacTypes.BoolValue
	KMSMasterKeyID iacTypes.StringValue
}
