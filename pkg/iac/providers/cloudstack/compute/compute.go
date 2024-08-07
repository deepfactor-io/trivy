package compute

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type Compute struct {
	Instances []Instance
}

type Instance struct {
	Metadata iacTypes.Metadata
	UserData iacTypes.StringValue // not b64 encoded pls
}
