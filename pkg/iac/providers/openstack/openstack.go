package openstack

import (
	iacTypes "github.com/deepfactor-io/trivy/v3/pkg/iac/types"
)

type OpenStack struct {
	Compute    Compute
	Networking Networking
}

type Compute struct {
	Instances []Instance
	Firewall  Firewall
}

type Firewall struct {
	AllowRules []FirewallRule
	DenyRules  []FirewallRule
}

type FirewallRule struct {
	Metadata        iacTypes.Metadata
	Source          iacTypes.StringValue
	Destination     iacTypes.StringValue
	SourcePort      iacTypes.StringValue
	DestinationPort iacTypes.StringValue
	Enabled         iacTypes.BoolValue
}

type Instance struct {
	Metadata      iacTypes.Metadata
	AdminPassword iacTypes.StringValue
}
