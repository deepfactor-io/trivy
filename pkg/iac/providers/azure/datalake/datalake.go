package datalake

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type DataLake struct {
	Stores []Store
}

type Store struct {
	Metadata         iacTypes.Metadata
	EnableEncryption iacTypes.BoolValue
}
