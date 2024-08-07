package s3

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/s3"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) s3.S3 {

	a := &adapter{
		modules:   modules,
		bucketMap: make(map[string]*s3.Bucket),
	}

	return s3.S3{
		Buckets: a.adaptBuckets(),
	}
}
