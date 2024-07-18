package database

import (
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/database"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/azure"
)

func addFirewallRule(resource azure.Resource) []database.FirewallRule {
	var rules []database.FirewallRule
	for _, rule := range resource.Properties.GetMapValue("firewallRules").AsMap() {
		rules = append(rules, database.FirewallRule{
			Metadata: rule.Metadata,
			StartIP:  rule.GetMapValue("startIpAddress").AsStringValue("", rule.Metadata),
			EndIP:    rule.GetMapValue("endIpAddress").AsStringValue("", rule.Metadata),
		})
	}
	return rules
}
