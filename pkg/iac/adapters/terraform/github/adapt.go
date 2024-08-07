package github

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/github/branch_protections"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/github/repositories"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/adapters/terraform/github/secrets"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/github"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) github.GitHub {
	return github.GitHub{
		Repositories:       repositories.Adapt(modules),
		EnvironmentSecrets: secrets.Adapt(modules),
		BranchProtections:  branch_protections.Adapt(modules),
	}
}
