package ecs

import (
	"encoding/json"

	iacTypes "github.com/deepfactor-io/trivy/pkg/iac/types"
)

type ECS struct {
	Clusters        []Cluster
	TaskDefinitions []TaskDefinition
}

type Cluster struct {
	Metadata iacTypes.Metadata
	Settings ClusterSettings
}

type ClusterSettings struct {
	Metadata                 iacTypes.Metadata
	ContainerInsightsEnabled iacTypes.BoolValue
}

type TaskDefinition struct {
	Metadata             iacTypes.Metadata
	Volumes              []Volume
	ContainerDefinitions []ContainerDefinition
}

func CreateDefinitionsFromString(metadata iacTypes.Metadata, str string) ([]ContainerDefinition, error) {
	var containerDefinitionsJSON []containerDefinitionJSON
	if err := json.Unmarshal([]byte(str), &containerDefinitionsJSON); err != nil {
		return nil, err
	}
	var definitions []ContainerDefinition
	for _, j := range containerDefinitionsJSON {
		definitions = append(definitions, j.convert(metadata))
	}
	return definitions, nil
}

// see https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html
type containerDefinitionJSON struct {
	Name         string            `json:"name"`
	Image        string            `json:"image"`
	CPU          int               `json:"cpu"`
	Memory       int               `json:"memory"`
	Essential    bool              `json:"essential"`
	PortMappings []portMappingJSON `json:"portMappings"`
	EnvVars      []envVarJSON      `json:"environment"`
	Privileged   bool              `json:"privileged"`
}

type envVarJSON struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type portMappingJSON struct {
	ContainerPort int `json:"containerPort"`
	HostPort      int `json:"hostPort"`
}

func (j containerDefinitionJSON) convert(metadata iacTypes.Metadata) ContainerDefinition {
	var mappings []PortMapping
	for _, jMapping := range j.PortMappings {
		mappings = append(mappings, PortMapping{
			ContainerPort: iacTypes.Int(jMapping.ContainerPort, metadata),
			HostPort:      iacTypes.Int(jMapping.HostPort, metadata),
		})
	}
	var envVars []EnvVar
	for _, env := range j.EnvVars {
		envVars = append(envVars, EnvVar(env))
	}
	return ContainerDefinition{
		Metadata:     metadata,
		Name:         iacTypes.String(j.Name, metadata),
		Image:        iacTypes.String(j.Image, metadata),
		CPU:          iacTypes.Int(j.CPU, metadata),
		Memory:       iacTypes.Int(j.Memory, metadata),
		Essential:    iacTypes.Bool(j.Essential, metadata),
		PortMappings: mappings,
		Environment:  envVars,
		Privileged:   iacTypes.Bool(j.Privileged, metadata),
	}
}

type ContainerDefinition struct {
	Metadata iacTypes.Metadata
	Name     iacTypes.StringValue
	Image    iacTypes.StringValue
	// TODO: CPU and Memory are strings
	// https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html#cfn-ecs-taskdefinition-cpu
	CPU          iacTypes.IntValue
	Memory       iacTypes.IntValue
	Essential    iacTypes.BoolValue
	PortMappings []PortMapping
	Environment  []EnvVar
	Privileged   iacTypes.BoolValue
}

type EnvVar struct {
	Name  string
	Value string
}

type PortMapping struct {
	ContainerPort iacTypes.IntValue
	HostPort      iacTypes.IntValue
}

type Volume struct {
	Metadata               iacTypes.Metadata
	EFSVolumeConfiguration EFSVolumeConfiguration
}

type EFSVolumeConfiguration struct {
	Metadata                 iacTypes.Metadata
	TransitEncryptionEnabled iacTypes.BoolValue
}
