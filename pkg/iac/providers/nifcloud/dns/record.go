package dns

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

const ZoneRegistrationAuthTxt = "nifty-dns-verify="

type Record struct {
	Metadata iacTypes.Metadata
	Type     iacTypes.StringValue
	Record   iacTypes.StringValue
}
