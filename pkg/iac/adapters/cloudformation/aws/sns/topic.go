package sns

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/sns"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

func getTopics(ctx parser.FileContext) (topics []sns.Topic) {
	for _, r := range ctx.GetResourcesByType("AWS::SNS::Topic") {

		topic := sns.Topic{
			Metadata: r.Metadata(),
			ARN:      types.StringDefault("", r.Metadata()),
			Encryption: sns.Encryption{
				Metadata: r.Metadata(),
				KMSKeyID: r.GetStringProperty("KmsMasterKeyId"),
			},
		}

		topics = append(topics, topic)
	}
	return topics
}
