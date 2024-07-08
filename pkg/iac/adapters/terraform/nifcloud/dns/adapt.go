package dns

import (
	"github.com/deepfactor-io/trivy/pkg/iac/providers/nifcloud/dns"
	"github.com/deepfactor-io/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) dns.DNS {
	return dns.DNS{
		Records: adaptRecords(modules),
	}
}
