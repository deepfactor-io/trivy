package nifcloud

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/nifcloud/computing"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/nifcloud/dns"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/nifcloud/nas"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/nifcloud/network"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/nifcloud/rdb"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/nifcloud/sslcertificate"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/nifcloud"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) nifcloud.Nifcloud {
	return nifcloud.Nifcloud{
		Computing:      computing.Adapt(modules),
		DNS:            dns.Adapt(modules),
		NAS:            nas.Adapt(modules),
		Network:        network.Adapt(modules),
		RDB:            rdb.Adapt(modules),
		SSLCertificate: sslcertificate.Adapt(modules),
	}
}
