package container

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/azure/container"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/azure"
)

func Adapt(deployment azure.Deployment) container.Container {
	return container.Container{
		KubernetesClusters: adaptKubernetesClusters(deployment),
	}
}

func adaptKubernetesClusters(deployment azure.Deployment) []container.KubernetesCluster {

	return nil
}
