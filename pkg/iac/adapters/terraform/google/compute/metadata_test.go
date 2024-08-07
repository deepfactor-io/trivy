package compute

import (
	"testing"

	"github.com/deepfactor-io/trivy/v3/internal/testutil"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/tftestutil"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/google/compute"
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

func Test_adaptProjectMetadata(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  compute.ProjectMetadata
	}{
		{
			name: "defined",
			terraform: `
			resource "google_compute_project_metadata" "example" {
				metadata = {
				  enable-oslogin = true
				}
			  }
`,
			expected: compute.ProjectMetadata{
				Metadata:      iacTypes.NewTestMetadata(),
				EnableOSLogin: iacTypes.Bool(true, iacTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "google_compute_project_metadata" "example" {
				metadata = {
				}
			  }
`,
			expected: compute.ProjectMetadata{
				Metadata:      iacTypes.NewTestMetadata(),
				EnableOSLogin: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptProjectMetadata(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
