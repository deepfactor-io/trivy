package terraform

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/options"
)

func Test_OS_FS(t *testing.T) {
	s := New(
		options.ScannerWithDebug(os.Stderr),
		options.ScannerWithEmbeddedPolicies(true),
		options.ScannerWithEmbeddedLibraries(true),
	)
	results, err := s.ScanFS(context.TODO(), os.DirFS("testdata"), "fail")
	require.NoError(t, err)
	assert.NotEmpty(t, results.GetFailed())
}
