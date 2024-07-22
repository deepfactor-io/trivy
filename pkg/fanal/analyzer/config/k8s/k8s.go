package k8s

import (
	"github.com/deepfactor-io/trivy/v3/pkg/fanal/analyzer"
	"github.com/deepfactor-io/trivy/v3/pkg/fanal/analyzer/config"
	"github.com/deepfactor-io/trivy/v3/pkg/misconf"
)

const (
	analyzerType = analyzer.TypeKubernetes
	version      = 1
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzerType, newKubernetesConfigAnalyzer)
}

// kubernetesConfigAnalyzer is an analyzer for detecting misconfigurations in Kubernetes config files.
// It embeds config.Analyzer so it can implement analyzer.PostAnalyzer.
type kubernetesConfigAnalyzer struct {
	*config.Analyzer
}

func newKubernetesConfigAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	a, err := config.NewAnalyzer(analyzerType, version, misconf.NewKubernetesScanner, opts)
	if err != nil {
		return nil, err
	}
	return &kubernetesConfigAnalyzer{Analyzer: a}, nil
}
