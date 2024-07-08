package flag_test

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deepfactor-io/trivy/pkg/flag"
	"github.com/deepfactor-io/trivy/pkg/types"
)

func TestScanFlagGroup_ToOptions(t *testing.T) {
	type fields struct {
		skipDirs    []string
		skipFiles   []string
		offlineScan bool
		scanners    string
	}
	tests := []struct {
		name      string
		args      []string
		fields    fields
		want      flag.ScanOptions
		assertion require.ErrorAssertionFunc
	}{
		{
			name:   "happy path",
			args:   []string{"alpine:latest"},
			fields: fields{},
			want: flag.ScanOptions{
				Target: "alpine:latest",
			},
			assertion: require.NoError,
		},
		{
			name: "happy path for configs",
			args: []string{"alpine:latest"},
			fields: fields{
				scanners: "misconfig",
			},
			want: flag.ScanOptions{
				Target:   "alpine:latest",
				Scanners: types.Scanners{types.MisconfigScanner},
			},
			assertion: require.NoError,
		},
		{
			name:      "without target (args)",
			args:      []string{},
			fields:    fields{},
			want:      flag.ScanOptions{},
			assertion: require.NoError,
		},
		{
			name: "with two or more targets (args)",
			args: []string{
				"alpine:latest",
				"nginx:latest",
			},
			fields:    fields{},
			want:      flag.ScanOptions{},
			assertion: require.NoError,
		},
		{
			name: "skip two files",
			fields: fields{
				skipFiles: []string{
					"file1",
					"file2",
				},
			},
			want: flag.ScanOptions{
				SkipFiles: []string{
					"file1",
					"file2",
				},
			},
			assertion: require.NoError,
		},
		{
			name: "skip two folders",
			fields: fields{
				skipDirs: []string{
					"dir1",
					"dir2",
				},
			},
			want: flag.ScanOptions{
				SkipDirs: []string{
					"dir1",
					"dir2",
				},
			},
			assertion: require.NoError,
		},
		{
			name: "offline scan",
			fields: fields{
				offlineScan: true,
			},
			want: flag.ScanOptions{
				OfflineScan: true,
			},
			assertion: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			setSliceValue(flag.SkipDirsFlag.ConfigName, tt.fields.skipDirs)
			setSliceValue(flag.SkipFilesFlag.ConfigName, tt.fields.skipFiles)
			setValue(flag.OfflineScanFlag.ConfigName, tt.fields.offlineScan)
			setValue(flag.ScannersFlag.ConfigName, tt.fields.scanners)

			// Assert options
			f := &flag.ScanFlagGroup{
				SkipDirs:    flag.SkipDirsFlag.Clone(),
				SkipFiles:   flag.SkipFilesFlag.Clone(),
				OfflineScan: flag.OfflineScanFlag.Clone(),
				Scanners:    flag.ScannersFlag.Clone(),
			}

			got, err := f.ToOptions(tt.args)
			tt.assertion(t, err)
			assert.Equalf(t, tt.want, got, "ToOptions()")
		})
	}
}
