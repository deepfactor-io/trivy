package sslcertificate

import (
	iacTypes "github.com/deepfactor-io/trivy/pkg/iac/types"
)

type ServerCertificate struct {
	Metadata   iacTypes.Metadata
	Expiration iacTypes.TimeValue
}
