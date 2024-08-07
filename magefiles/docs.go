//go:build mage_docs

package main

import (
	"os"

	"github.com/spf13/cobra/doc"

	"github.com/deepfactor-io/trivy/v3/pkg/commands"
	"github.com/deepfactor-io/trivy/v3/pkg/flag"
	"github.com/deepfactor-io/trivy/v3/pkg/log"
)

// Generate CLI references
func main() {
	// Set a dummy path for the documents
	flag.CacheDirFlag.Default = "/path/to/cache"
	flag.ModuleDirFlag.Default = "$HOME/.trivy/modules"

	// Set a dummy path not to load plugins
	os.Setenv("XDG_DATA_HOME", os.TempDir())

	cmd := commands.NewApp()
	cmd.DisableAutoGenTag = true
	if err := doc.GenMarkdownTree(cmd, "./docs/docs/references/configuration/cli"); err != nil {
		log.Fatal("Fatal error", log.Err(err))
	}
}
