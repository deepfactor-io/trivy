package azure

import (
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/appservice"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/authorization"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/compute"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/container"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/database"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/datafactory"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/datalake"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/keyvault"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/monitor"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/network"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/securitycenter"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/storage"
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/synapse"
)

type Azure struct {
	AppService     appservice.AppService
	Authorization  authorization.Authorization
	Compute        compute.Compute
	Container      container.Container
	Database       database.Database
	DataFactory    datafactory.DataFactory
	DataLake       datalake.DataLake
	KeyVault       keyvault.KeyVault
	Monitor        monitor.Monitor
	Network        network.Network
	SecurityCenter securitycenter.SecurityCenter
	Storage        storage.Storage
	Synapse        synapse.Synapse
}
