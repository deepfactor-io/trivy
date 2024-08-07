package config

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type Config struct {
	ConfigurationAggregrator ConfigurationAggregrator
}

type ConfigurationAggregrator struct {
	Metadata         iacTypes.Metadata
	SourceAllRegions iacTypes.BoolValue
}
