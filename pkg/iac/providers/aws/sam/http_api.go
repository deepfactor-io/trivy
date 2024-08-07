package sam

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type HttpAPI struct {
	Metadata             iacTypes.Metadata
	Name                 iacTypes.StringValue
	AccessLogging        AccessLogging
	DefaultRouteSettings RouteSettings
	DomainConfiguration  DomainConfiguration
}

type RouteSettings struct {
	Metadata               iacTypes.Metadata
	LoggingEnabled         iacTypes.BoolValue
	DataTraceEnabled       iacTypes.BoolValue
	DetailedMetricsEnabled iacTypes.BoolValue
}
