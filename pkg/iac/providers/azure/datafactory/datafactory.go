package datafactory

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type DataFactory struct {
	DataFactories []Factory
}

type Factory struct {
	Metadata            iacTypes.Metadata
	EnablePublicNetwork iacTypes.BoolValue
}
