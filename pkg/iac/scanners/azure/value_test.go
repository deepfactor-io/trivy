package azure

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

func Test_ValueAsInt(t *testing.T) {
	val := NewValue(int64(10), types.NewTestMetadata())
	assert.Equal(t, 10, val.AsInt())
}
