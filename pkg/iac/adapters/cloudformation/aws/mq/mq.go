package mq

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/mq"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adapts an MQ instance
func Adapt(cfFile parser.FileContext) mq.MQ {
	return mq.MQ{
		Brokers: getBrokers(cfFile),
	}
}
