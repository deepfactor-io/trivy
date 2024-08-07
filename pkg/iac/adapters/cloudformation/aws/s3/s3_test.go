package s3

import (
	"testing"

	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/testutil"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/s3"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected s3.S3
	}{
		{
			name: "complete s3 bucket",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  Key:
    Type: "AWS::KMS::Key"
  LoggingBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: logging-bucket
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-bucket
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              KMSMasterKeyID:
                Fn::GetAtt:
                  - Key
                  - Arn
              SSEAlgorithm: aws:kms
      AccessControl: AwsExecRead
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      LoggingConfiguration:
        DestinationBucketName: !Ref LoggingBucket
        LogFilePrefix: testing-logs
      LifecycleConfiguration:
        Rules:
          - Id: GlacierRule
            Prefix: glacier
            Status: Enabled
            ExpirationInDays: 365
      AccelerateConfiguration:
        AccelerationStatus: Enabled
      VersioningConfiguration:
        Status: Enabled
      WebsiteConfiguration:
        IndexDocument: index.html
`,
			expected: s3.S3{
				Buckets: []s3.Bucket{
					{
						Name: types.StringTest("logging-bucket"),
					},
					{
						Name: types.StringTest("test-bucket"),
						Encryption: s3.Encryption{
							Enabled:   types.BoolTest(true),
							Algorithm: types.StringTest("aws:kms"),
							KMSKeyId:  types.StringTest("Key"),
						},
						ACL: types.StringTest("aws-exec-read"),
						PublicAccessBlock: &s3.PublicAccessBlock{
							BlockPublicACLs:       types.BoolTest(true),
							BlockPublicPolicy:     types.BoolTest(true),
							IgnorePublicACLs:      types.BoolTest(true),
							RestrictPublicBuckets: types.BoolTest(true),
						},
						Logging: s3.Logging{
							TargetBucket: types.StringTest("LoggingBucket"),
							Enabled:      types.BoolTest(true),
						},
						LifecycleConfiguration: []s3.Rules{
							{
								Status: types.StringTest("Enabled"),
							},
						},
						AccelerateConfigurationStatus: types.StringTest("Enabled"),
						Versioning: s3.Versioning{
							Enabled: types.BoolTest(true),
						},
						Website: &s3.Website{},
					},
				},
			},
		},
		{
			name: "empty s3 bucket",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-bucket`,
			expected: s3.S3{
				Buckets: []s3.Bucket{
					{
						Name: types.StringTest("test-bucket"),
						Encryption: s3.Encryption{
							Enabled: types.BoolDefault(false, types.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "incorrect SSE algorithm",
			source: `AWSTemplateFormatVersion: 2010-09-09
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-bucket
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              KMSMasterKeyID: alias/my-key
              SSEAlgorithm: aes256
`,
			expected: s3.S3{
				Buckets: []s3.Bucket{
					{
						Name: types.StringTest("test-bucket"),
						Encryption: s3.Encryption{
							Enabled:   types.BoolDefault(false, types.NewTestMetadata()),
							KMSKeyId:  types.StringTest("alias/my-key"),
							Algorithm: types.StringTest("aes256"),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}

}
