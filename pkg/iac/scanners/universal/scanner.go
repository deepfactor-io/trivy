package universal

import (
	"context"
	"io/fs"

	"github.com/deepfactor-io/trivy/pkg/iac/scan"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/azure/arm"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/cloudformation"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/dockerfile"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/helm"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/json"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/kubernetes"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/options"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/terraform"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/toml"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/yaml"
)

type nestableFSScanners interface {
	scanners.FSScanner
	options.ConfigurableScanner
}

var _ scanners.FSScanner = (*Scanner)(nil)

type Scanner struct {
	fsScanners []nestableFSScanners
}

func New(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		fsScanners: []nestableFSScanners{
			terraform.New(opts...),
			cloudformation.New(opts...),
			dockerfile.NewScanner(opts...),
			kubernetes.NewScanner(opts...),
			json.NewScanner(opts...),
			yaml.NewScanner(opts...),
			toml.NewScanner(opts...),
			helm.New(opts...),
			arm.New(opts...),
		},
	}
	return s
}

func (s *Scanner) Name() string {
	return "Universal"
}

func (s *Scanner) ScanFS(ctx context.Context, fsys fs.FS, dir string) (scan.Results, error) {
	var results scan.Results
	for _, inner := range s.fsScanners {
		innerResults, err := inner.ScanFS(ctx, fsys, dir)
		if err != nil {
			return nil, err
		}
		results = append(results, innerResults...)
	}
	return results, nil
}
