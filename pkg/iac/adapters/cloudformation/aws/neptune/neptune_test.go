package neptune

import (
	"testing"

	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/testutil"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/neptune"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected neptune.Neptune
	}{
		{
			name: "complete",
			source: `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  cluster:
    Type: AWS::Neptune::DBCluster
    Properties:
      StorageEncrypted: true
      KmsKeyId: key
      EnableCloudwatchLogsExports:
        - audit
`,
			expected: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						StorageEncrypted: types.BoolTest(true),
						KMSKeyID:         types.StringTest("key"),
						Logging: neptune.Logging{
							Audit: types.BoolTest(true),
						},
					},
				},
			},
		},
		{
			name: "empty",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  cluster:
    Type: AWS::Neptune::DBCluster
  `,
			expected: neptune.Neptune{
				Clusters: []neptune.Cluster{{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
