package tftestutil

import (
	"context"
	"testing"

	"github.com/deepfactor-io/trivy/v3/internal/testutil"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/terraform/parser"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/terraform"
)

func CreateModulesFromSource(t *testing.T, source, ext string) terraform.Modules {
	fs := testutil.CreateFS(t, map[string]string{
		"source" + ext: source,
	})
	p := parser.New(fs, "", parser.OptionStopOnHCLError(true))
	if err := p.ParseFS(context.TODO(), "."); err != nil {
		t.Fatal(err)
	}
	modules, _, err := p.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	return modules
}
