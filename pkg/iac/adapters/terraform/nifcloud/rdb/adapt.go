package rdb

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/nifcloud/rdb"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) rdb.RDB {
	return rdb.RDB{
		DBSecurityGroups: adaptDBSecurityGroups(modules),
		DBInstances:      adaptDBInstances(modules),
	}
}
