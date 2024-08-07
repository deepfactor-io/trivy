package state

import (
	"reflect"

	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/azure"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/cloudstack"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/digitalocean"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/github"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/google"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/kubernetes"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/nifcloud"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/openstack"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/oracle"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/rego/convert"
)

type State struct {
	AWS          aws.AWS
	Azure        azure.Azure
	CloudStack   cloudstack.CloudStack
	DigitalOcean digitalocean.DigitalOcean
	GitHub       github.GitHub
	Google       google.Google
	Kubernetes   kubernetes.Kubernetes
	OpenStack    openstack.OpenStack
	Oracle       oracle.Oracle
	Nifcloud     nifcloud.Nifcloud
}

func (a *State) ToRego() any {
	return convert.StructToRego(reflect.ValueOf(a))
}
