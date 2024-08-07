package s3

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/s3"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an S3 instance
func Adapt(cfFile parser.FileContext) s3.S3 {
	return s3.S3{
		Buckets: getBuckets(cfFile),
	}
}
