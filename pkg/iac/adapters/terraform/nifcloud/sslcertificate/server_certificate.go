package sslcertificate

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/nifcloud/sslcertificate"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/terraform"
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

func adaptServerCertificates(modules terraform.Modules) []sslcertificate.ServerCertificate {
	var serverCertificates []sslcertificate.ServerCertificate

	for _, resource := range modules.GetResourcesByType("nifcloud_ssl_certificate") {
		serverCertificates = append(serverCertificates, adaptServerCertificate(resource))
	}
	return serverCertificates
}

func adaptServerCertificate(resource *terraform.Block) sslcertificate.ServerCertificate {
	certificateAttr := resource.GetAttribute("certificate")
	expiryDateVal := iacTypes.TimeUnresolvable(resource.GetMetadata())

	if certificateAttr.IsNotNil() {
		expiryDateVal = iacTypes.TimeUnresolvable(certificateAttr.GetMetadata())
		if certificateAttr.IsString() {
			certificateString := certificateAttr.Value().AsString()
			if block, _ := pem.Decode([]byte(certificateString)); block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					expiryDateVal = iacTypes.Time(cert.NotAfter, certificateAttr.GetMetadata())
				}
			}
		}
	}

	return sslcertificate.ServerCertificate{
		Metadata:   resource.GetMetadata(),
		Expiration: expiryDateVal,
	}
}
