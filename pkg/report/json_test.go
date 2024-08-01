package report_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/deepfactor-io/trivy/v3/pkg/report"
	"github.com/deepfactor-io/trivy/v3/pkg/types"
)

func TestReportWriter_JSON(t *testing.T) {
	testCases := []struct {
		name          string
		detectedVulns []types.DetectedVulnerability
		want          types.Report
	}{
		{
			name: "happy path",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2020-0001",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-0001",
					Vulnerability: dbTypes.Vulnerability{
						Title:       "foobar",
						Description: "baz",
						Severity:    "HIGH",
						VendorSeverity: map[dbTypes.SourceID]dbTypes.Severity{
							vulnerability.NVD: dbTypes.SeverityHigh,
						},
					},
				},
			},
			want: types.Report{
				SchemaVersion: 2,
				ArtifactName:  "alpine:3.14",
				Results: types.Results{
					types.Result{
						Target: "foojson",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2020-0001",
								PkgName:          "foo",
								InstalledVersion: "1.2.3",
								FixedVersion:     "3.4.5",
								PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-0001",
								Vulnerability: dbTypes.Vulnerability{
									Title:       "foobar",
									Description: "baz",
									Severity:    "HIGH",
									VendorSeverity: map[dbTypes.SourceID]dbTypes.Severity{
										vulnerability.NVD: dbTypes.SeverityHigh,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jsonWritten := bytes.NewBuffer(nil)
			jw := report.JSONWriter{
				Output: jsonWritten,
			}

			inputResults := types.Report{
				SchemaVersion: 2,
				ArtifactName:  "alpine:3.14",
				Results: types.Results{
					{
						Target:          "foojson",
						Vulnerabilities: tc.detectedVulns,
					},
				},
			}

			err := jw.Write(inputResults)
			assert.NoError(t, err)

			var got types.Report
			err = json.Unmarshal(jsonWritten.Bytes(), &got)
			assert.NoError(t, err, "invalid json written")

			assert.Equal(t, tc.want, got, tc.name)
		})
	}
}
