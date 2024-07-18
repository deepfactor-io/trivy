package azure

import (
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/azure/appservice"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/azure/authorization"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/azure/compute"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/azure/container"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/azure/database"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/azure/datafactory"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/azure/datalake"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/azure/keyvault"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/azure/monitor"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/azure/network"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/azure/securitycenter"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/azure/storage"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/terraform/azure/synapse"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure"
	"github.com/deepfactor-io/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) azure.Azure {
	return azure.Azure{
		AppService:     appservice.Adapt(modules),
		Authorization:  authorization.Adapt(modules),
		Compute:        compute.Adapt(modules),
		Container:      container.Adapt(modules),
		Database:       database.Adapt(modules),
		DataFactory:    datafactory.Adapt(modules),
		DataLake:       datalake.Adapt(modules),
		KeyVault:       keyvault.Adapt(modules),
		Monitor:        monitor.Adapt(modules),
		Network:        network.Adapt(modules),
		SecurityCenter: securitycenter.Adapt(modules),
		Storage:        storage.Adapt(modules),
		Synapse:        synapse.Adapt(modules),
	}
}
