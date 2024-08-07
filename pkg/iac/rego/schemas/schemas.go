package schemas

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

var SchemaMap = map[types.Source]Schema{
	types.SourceDefsec:     Cloud,
	types.SourceCloud:      Cloud,
	types.SourceKubernetes: Kubernetes,
	types.SourceRbac:       Kubernetes,
	types.SourceDockerfile: Dockerfile,
	types.SourceTOML:       Anything,
	types.SourceYAML:       Anything,
	types.SourceJSON:       Anything,
}
