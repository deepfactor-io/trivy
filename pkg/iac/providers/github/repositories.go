package github

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type Repository struct {
	Metadata            iacTypes.Metadata
	Public              iacTypes.BoolValue
	VulnerabilityAlerts iacTypes.BoolValue
	Archived            iacTypes.BoolValue
}

func (r Repository) IsArchived() bool {
	return r.Archived.IsTrue()
}
