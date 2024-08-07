package synapse

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type Synapse struct {
	Workspaces []Workspace
}

type Workspace struct {
	Metadata                    iacTypes.Metadata
	EnableManagedVirtualNetwork iacTypes.BoolValue
}
