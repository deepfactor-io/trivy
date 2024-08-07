package rules

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scan"
)

type RegisteredRule struct {
	scan.Rule
	Number int
}

func (r *RegisteredRule) GetRule() scan.Rule {
	return r.Rule
}

func (r *RegisteredRule) AddLink(link string) {
	r.Rule.Links = append([]string{link}, r.Rule.Links...)
}
