package config

import (
	"sort"
<<<<<<< HEAD
	"strings"

	"golang.org/x/xerrors"

	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer/config/helm"

	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer/config/dockerfile"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer/config/json"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer/config/terraform"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer/config/yaml"
	"github.com/deepfactor-io/trivy/pkg/fanal/types"
=======
>>>>>>> fd5cafb26dfebcea6939572098650f79bafb430c
)

type ScannerOption struct {
	Trace                   bool
	RegoOnly                bool
	Namespaces              []string
	PolicyPaths             []string
	DataPaths               []string
	DisableEmbeddedPolicies bool

	HelmValues       []string
	HelmValueFiles   []string
	HelmFileValues   []string
	HelmStringValues []string
	TerraformTFVars  []string
}

func (o *ScannerOption) Sort() {
	sort.Strings(o.Namespaces)
	sort.Strings(o.PolicyPaths)
	sort.Strings(o.DataPaths)
}
