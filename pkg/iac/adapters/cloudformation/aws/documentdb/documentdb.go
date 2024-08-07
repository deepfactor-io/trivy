package documentdb

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/providers/aws/documentdb"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/parser"
)

// Adapt adaps a documentDB instance
func Adapt(cfFile parser.FileContext) documentdb.DocumentDB {
	return documentdb.DocumentDB{
		Clusters: getClusters(cfFile),
	}
}
