package all

import (
	_ "github.com/deepfactor-io/trivy/v3/pkg/fanal/analyzer/config/azurearm"
	_ "github.com/deepfactor-io/trivy/v3/pkg/fanal/analyzer/config/cloudformation"
	_ "github.com/deepfactor-io/trivy/v3/pkg/fanal/analyzer/config/dockerfile"
	_ "github.com/deepfactor-io/trivy/v3/pkg/fanal/analyzer/config/helm"
	_ "github.com/deepfactor-io/trivy/v3/pkg/fanal/analyzer/config/k8s"
	_ "github.com/deepfactor-io/trivy/v3/pkg/fanal/analyzer/config/terraform"
	_ "github.com/deepfactor-io/trivy/v3/pkg/fanal/analyzer/config/terraformplan"
)
