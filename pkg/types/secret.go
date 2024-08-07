package types

import (
	ftypes "github.com/deepfactor-io/trivy/v3/pkg/fanal/types"
)

type DetectedSecret ftypes.SecretFinding

func (DetectedSecret) findingType() FindingType { return FindingTypeSecret }
