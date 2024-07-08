package google

import (
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/google/bigquery"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/google/compute"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/google/dns"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/google/gke"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/google/iam"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/google/kms"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/google/sql"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/google/storage"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/google"
	"github.com/deepfactor-io/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) google.Google {
	return google.Google{
		BigQuery: bigquery.Adapt(modules),
		Compute:  compute.Adapt(modules),
		DNS:      dns.Adapt(modules),
		GKE:      gke.Adapt(modules),
		KMS:      kms.Adapt(modules),
		IAM:      iam.Adapt(modules),
		SQL:      sql.Adapt(modules),
		Storage:  storage.Adapt(modules),
	}
}
