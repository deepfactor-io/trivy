package accessanalyzer

import (
	"testing"

	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/testutil"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/accessanalyzer"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected accessanalyzer.AccessAnalyzer
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  Analyzer:
    Type: 'AWS::AccessAnalyzer::Analyzer'
    Properties:
      AnalyzerName: MyAccountAnalyzer
`,
			expected: accessanalyzer.AccessAnalyzer{
				Analyzers: []accessanalyzer.Analyzer{
					{
						Name: types.StringTest("MyAccountAnalyzer"),
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  Analyzer:
    Type: 'AWS::AccessAnalyzer::Analyzer'
`,
			expected: accessanalyzer.AccessAnalyzer{
				Analyzers: []accessanalyzer.Analyzer{
					{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
