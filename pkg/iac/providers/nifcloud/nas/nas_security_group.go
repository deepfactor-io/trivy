package nas

import (
	iacTypes "github.com/deepfactor-io/trivy/pkg/iac/types"
)

type NASSecurityGroup struct {
	Metadata    iacTypes.Metadata
	Description iacTypes.StringValue
	CIDRs       []iacTypes.StringValue
}
