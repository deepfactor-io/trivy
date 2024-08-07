package accessanalyzer

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/accessanalyzer"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

func getAccessAnalyzer(ctx parser.FileContext) (analyzers []accessanalyzer.Analyzer) {

	analyzersList := ctx.GetResourcesByType("AWS::AccessAnalyzer::Analyzer")

	for _, r := range analyzersList {
		aa := accessanalyzer.Analyzer{
			Metadata: r.Metadata(),
			Name:     r.GetStringProperty("AnalyzerName"),
			ARN:      r.StringDefault(""),
			Active:   types.BoolDefault(false, r.Metadata()),
		}

		analyzers = append(analyzers, aa)
	}
	return analyzers
}
