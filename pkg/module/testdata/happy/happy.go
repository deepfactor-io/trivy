//go:generate tinygo build -o happy.wasm -scheduler=none -target=wasi --no-debug happy.go
//go:build tinygo.wasm

package main

import (
	"github.com/deepfactor-io/trivy/v3/pkg/module/api"
	"github.com/deepfactor-io/trivy/v3/pkg/module/serialize"
	"github.com/deepfactor-io/trivy/v3/pkg/module/wasm"
)

const (
	moduleVersion = 1
	moduleName    = "happy"
)

func main() {
	wasm.RegisterModule(HappyModule{})
}

type HappyModule struct{}

func (HappyModule) Version() int {
	return moduleVersion
}

func (HappyModule) Name() string {
	return moduleName
}

func (HappyModule) RequiredFiles() []string {
	return []string{}
}

func (s HappyModule) Analyze(_ string) (*serialize.AnalysisResult, error) {
	return nil, nil
}

func (HappyModule) PostScanSpec() serialize.PostScanSpec {
	return serialize.PostScanSpec{
		Action: api.ActionInsert, // Add new vulnerabilities
	}
}

func (HappyModule) PostScan(_ serialize.Results) (serialize.Results, error) {
	return nil, nil
}
