package arm

import (
	"context"

	"github.com/deepfactor-io/trivy/pkg/iac/adapters/arm/appservice"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/arm/authorization"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/arm/compute"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/arm/container"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/arm/database"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/arm/datafactory"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/arm/datalake"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/arm/keyvault"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/arm/monitor"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/arm/network"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/arm/securitycenter"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/arm/storage"
	"github.com/deepfactor-io/trivy/pkg/iac/adapters/arm/synapse"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure"
	scanner "github.com/deepfactor-io/trivy/pkg/iac/scanners/azure"
	"github.com/deepfactor-io/trivy/pkg/iac/state"
)

// Adapt adapts an azure arm instance
func Adapt(ctx context.Context, deployment scanner.Deployment) *state.State {
	return &state.State{
		Azure: adaptAzure(deployment),
	}
}

func adaptAzure(deployment scanner.Deployment) azure.Azure {

	return azure.Azure{
		AppService:     appservice.Adapt(deployment),
		Authorization:  authorization.Adapt(deployment),
		Compute:        compute.Adapt(deployment),
		Container:      container.Adapt(deployment),
		Database:       database.Adapt(deployment),
		DataFactory:    datafactory.Adapt(deployment),
		DataLake:       datalake.Adapt(deployment),
		KeyVault:       keyvault.Adapt(deployment),
		Monitor:        monitor.Adapt(deployment),
		Network:        network.Adapt(deployment),
		SecurityCenter: securitycenter.Adapt(deployment),
		Storage:        storage.Adapt(deployment),
		Synapse:        synapse.Adapt(deployment),
	}

}
