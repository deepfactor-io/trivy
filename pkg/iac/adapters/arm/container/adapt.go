package container

import (
	"github.com/deepfactor-io/trivy/pkg/iac/providers/azure/container"
	"github.com/deepfactor-io/trivy/pkg/iac/scanners/azure"
)

func Adapt(deployment azure.Deployment) container.Container {
	return container.Container{
		KubernetesClusters: adaptKubernetesClusters(deployment),
	}
}

func adaptKubernetesClusters(deployment azure.Deployment) []container.KubernetesCluster {

	return nil
}
