package sslcertificate

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type ServerCertificate struct {
	Metadata   iacTypes.Metadata
	Expiration iacTypes.TimeValue
}
