package rdb

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type DBInstance struct {
	Metadata                  iacTypes.Metadata
	BackupRetentionPeriodDays iacTypes.IntValue
	Engine                    iacTypes.StringValue
	EngineVersion             iacTypes.StringValue
	NetworkID                 iacTypes.StringValue
	PublicAccess              iacTypes.BoolValue
}
