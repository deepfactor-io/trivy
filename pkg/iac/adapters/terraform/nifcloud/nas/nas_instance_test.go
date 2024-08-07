package nas

import (
	"testing"

	"github.com/deepfactor-io/trivy/v3/internal/testutil"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/tftestutil"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/nifcloud/nas"
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

func Test_adaptNASInstances(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []nas.NASInstance
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_nas_instance" "example" {
				network_id = "example-network"
			}
`,
			expected: []nas.NASInstance{{
				Metadata:  iacTypes.NewTestMetadata(),
				NetworkID: iacTypes.String("example-network", iacTypes.NewTestMetadata()),
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_nas_instance" "example" {
			}
`,

			expected: []nas.NASInstance{{
				Metadata:  iacTypes.NewTestMetadata(),
				NetworkID: iacTypes.String("net-COMMON_PRIVATE", iacTypes.NewTestMetadata()),
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptNASInstances(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
