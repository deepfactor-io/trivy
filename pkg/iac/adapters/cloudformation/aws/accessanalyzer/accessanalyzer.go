package accessanalyzer

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/accessanalyzer"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an AccessAnalyzer instance
func Adapt(cfFile parser.FileContext) accessanalyzer.AccessAnalyzer {
	return accessanalyzer.AccessAnalyzer{
		Analyzers: getAccessAnalyzer(cfFile),
	}
}
