package aws

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/apigateway"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/athena"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/cloudfront"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/cloudtrail"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/cloudwatch"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/codebuild"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/config"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/documentdb"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/dynamodb"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/ec2"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/ecr"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/ecs"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/efs"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/eks"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/elasticache"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/elasticsearch"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/elb"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/iam"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/kinesis"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/lambda"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/mq"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/msk"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/neptune"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/rds"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/redshift"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/s3"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/sam"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/sns"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/sqs"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/ssm"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/cloudformation/aws/workspaces"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts a Cloudformation AWS instance
func Adapt(cfFile parser.FileContext) aws.AWS {
	return aws.AWS{
		APIGateway:    apigateway.Adapt(cfFile),
		Athena:        athena.Adapt(cfFile),
		Cloudfront:    cloudfront.Adapt(cfFile),
		CloudTrail:    cloudtrail.Adapt(cfFile),
		CloudWatch:    cloudwatch.Adapt(cfFile),
		CodeBuild:     codebuild.Adapt(cfFile),
		Config:        config.Adapt(cfFile),
		DocumentDB:    documentdb.Adapt(cfFile),
		DynamoDB:      dynamodb.Adapt(cfFile),
		EC2:           ec2.Adapt(cfFile),
		ECR:           ecr.Adapt(cfFile),
		ECS:           ecs.Adapt(cfFile),
		EFS:           efs.Adapt(cfFile),
		IAM:           iam.Adapt(cfFile),
		EKS:           eks.Adapt(cfFile),
		ElastiCache:   elasticache.Adapt(cfFile),
		Elasticsearch: elasticsearch.Adapt(cfFile),
		ELB:           elb.Adapt(cfFile),
		MSK:           msk.Adapt(cfFile),
		MQ:            mq.Adapt(cfFile),
		Kinesis:       kinesis.Adapt(cfFile),
		Lambda:        lambda.Adapt(cfFile),
		Neptune:       neptune.Adapt(cfFile),
		RDS:           rds.Adapt(cfFile),
		Redshift:      redshift.Adapt(cfFile),
		S3:            s3.Adapt(cfFile),
		SAM:           sam.Adapt(cfFile),
		SNS:           sns.Adapt(cfFile),
		SQS:           sqs.Adapt(cfFile),
		SSM:           ssm.Adapt(cfFile),
		WorkSpaces:    workspaces.Adapt(cfFile),
	}
}
