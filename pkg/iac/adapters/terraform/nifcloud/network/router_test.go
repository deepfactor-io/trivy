package network

import (
	"testing"

	"github.com/deepfactor-io/trivy/v3/internal/testutil"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/tftestutil"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/nifcloud/network"
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

func Test_adaptRouters(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []network.Router
	}{
		{
			name: "configured",
			terraform: `
			resource "nifcloud_router" "example" {
				security_group  = "example-security-group"
				network_interface  {
					network_id    = "net-COMMON_PRIVATE"
				}
			}
`,
			expected: []network.Router{{
				Metadata:      iacTypes.NewTestMetadata(),
				SecurityGroup: iacTypes.String("example-security-group", iacTypes.NewTestMetadata()),
				NetworkInterfaces: []network.NetworkInterface{
					{
						Metadata:  iacTypes.NewTestMetadata(),
						NetworkID: iacTypes.String("net-COMMON_PRIVATE", iacTypes.NewTestMetadata()),
					},
				},
			}},
		},
		{
			name: "defaults",
			terraform: `
			resource "nifcloud_router" "example" {
				network_interface  {
				}
			}
`,

			expected: []network.Router{{
				Metadata:      iacTypes.NewTestMetadata(),
				SecurityGroup: iacTypes.String("", iacTypes.NewTestMetadata()),
				NetworkInterfaces: []network.NetworkInterface{
					{
						Metadata:  iacTypes.NewTestMetadata(),
						NetworkID: iacTypes.String("", iacTypes.NewTestMetadata()),
					},
				},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptRouters(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
