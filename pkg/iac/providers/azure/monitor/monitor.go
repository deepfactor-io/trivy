package monitor

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type Monitor struct {
	LogProfiles []LogProfile
}

type LogProfile struct {
	Metadata        iacTypes.Metadata
	RetentionPolicy RetentionPolicy
	Categories      []iacTypes.StringValue
	Locations       []iacTypes.StringValue
}

type RetentionPolicy struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
	Days     iacTypes.IntValue
}
