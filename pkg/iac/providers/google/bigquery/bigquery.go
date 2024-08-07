package bigquery

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type BigQuery struct {
	Datasets []Dataset
}

type Dataset struct {
	Metadata     iacTypes.Metadata
	ID           iacTypes.StringValue
	AccessGrants []AccessGrant
}

const (
	SpecialGroupAllAuthenticatedUsers = "allAuthenticatedUsers"
)

type AccessGrant struct {
	Metadata     iacTypes.Metadata
	Role         iacTypes.StringValue
	Domain       iacTypes.StringValue
	SpecialGroup iacTypes.StringValue
}
