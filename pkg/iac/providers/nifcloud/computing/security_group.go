package computing

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type SecurityGroup struct {
	Metadata     iacTypes.Metadata
	Description  iacTypes.StringValue
	IngressRules []SecurityGroupRule
	EgressRules  []SecurityGroupRule
}

type SecurityGroupRule struct {
	Metadata    iacTypes.Metadata
	Description iacTypes.StringValue
	CIDR        iacTypes.StringValue
}
