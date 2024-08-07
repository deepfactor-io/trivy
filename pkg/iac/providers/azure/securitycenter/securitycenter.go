package securitycenter

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type SecurityCenter struct {
	Contacts      []Contact
	Subscriptions []SubscriptionPricing
}

type Contact struct {
	Metadata                 iacTypes.Metadata
	EnableAlertNotifications iacTypes.BoolValue
	Phone                    iacTypes.StringValue
}

const (
	TierFree     = "Free"
	TierStandard = "Standard"
)

type SubscriptionPricing struct {
	Metadata iacTypes.Metadata
	Tier     iacTypes.StringValue
}
