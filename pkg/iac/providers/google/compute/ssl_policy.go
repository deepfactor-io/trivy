package compute

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type SSLPolicy struct {
	Metadata          iacTypes.Metadata
	Name              iacTypes.StringValue
	Profile           iacTypes.StringValue
	MinimumTLSVersion iacTypes.StringValue
}
