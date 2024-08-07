package documentdb

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type DocumentDB struct {
	Clusters []Cluster
}

const (
	LogExportAudit    = "audit"
	LogExportProfiler = "profiler"
)

type Cluster struct {
	Metadata              iacTypes.Metadata
	Identifier            iacTypes.StringValue
	EnabledLogExports     []iacTypes.StringValue
	BackupRetentionPeriod iacTypes.IntValue
	Instances             []Instance
	StorageEncrypted      iacTypes.BoolValue
	KMSKeyID              iacTypes.StringValue
}

type Instance struct {
	Metadata iacTypes.Metadata
	KMSKeyID iacTypes.StringValue
}
