package rds

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type Classic struct {
	DBSecurityGroups []DBSecurityGroup
}

type DBSecurityGroup struct {
	Metadata types.Metadata
}
