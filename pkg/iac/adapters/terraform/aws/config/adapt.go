package config

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/config"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/terraform"
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

func Adapt(modules terraform.Modules) config.Config {
	return config.Config{
		ConfigurationAggregrator: adaptConfigurationAggregrator(modules),
	}
}

func adaptConfigurationAggregrator(modules terraform.Modules) config.ConfigurationAggregrator {
	configurationAggregrator := config.ConfigurationAggregrator{
		Metadata:         iacTypes.NewUnmanagedMetadata(),
		SourceAllRegions: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
	}

	for _, resource := range modules.GetResourcesByType("aws_config_configuration_aggregator") {
		configurationAggregrator.Metadata = resource.GetMetadata()
		aggregationBlock := resource.GetFirstMatchingBlock("account_aggregation_source", "organization_aggregation_source")
		if aggregationBlock.IsNil() {
			configurationAggregrator.SourceAllRegions = iacTypes.Bool(false, resource.GetMetadata())
		} else {
			allRegionsAttr := aggregationBlock.GetAttribute("all_regions")
			allRegionsVal := allRegionsAttr.AsBoolValueOrDefault(false, aggregationBlock)
			configurationAggregrator.SourceAllRegions = allRegionsVal
		}
	}
	return configurationAggregrator
}
