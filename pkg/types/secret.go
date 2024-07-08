package types

import (
	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
)

type DetectedSecret ftypes.SecretFinding

func (DetectedSecret) findingType() FindingType { return FindingTypeSecret }
