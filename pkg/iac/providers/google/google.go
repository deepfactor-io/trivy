package google

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/google/bigquery"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/google/compute"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/google/dns"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/google/gke"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/google/iam"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/google/kms"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/google/sql"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/google/storage"
)

type Google struct {
	BigQuery bigquery.BigQuery
	Compute  compute.Compute
	DNS      dns.DNS
	GKE      gke.GKE
	KMS      kms.KMS
	IAM      iam.IAM
	SQL      sql.SQL
	Storage  storage.Storage
}
