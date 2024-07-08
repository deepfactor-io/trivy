package nifcloud

import (
	"github.com/deepfactor-io/trivy/pkg/iac/providers/nifcloud/computing"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/nifcloud/dns"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/nifcloud/nas"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/nifcloud/network"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/nifcloud/rdb"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/nifcloud/sslcertificate"
)

type Nifcloud struct {
	Computing      computing.Computing
	DNS            dns.DNS
	NAS            nas.NAS
	Network        network.Network
	RDB            rdb.RDB
	SSLCertificate sslcertificate.SSLCertificate
}
