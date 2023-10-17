package utils

import (
	"fmt"
	"path/filepath"
	"strings"

	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/types"
	"github.com/samber/lo"
)

func DedupeNodePackages(lockFilePackages map[string]ftypes.Package, results []types.Result) []types.Result {
	// Map to store package keys that have to removed from lock file targets
	matchFoundInNode := map[string]struct{}{}

	// Resource deduplication for Node.js
	for i, result := range results {
		if result.Target != "Node.js" {
			continue
		}

		for j, pkg := range result.Packages {
			if pkg.ID == "" || pkg.FilePath == "" {
				continue
			}

			nodeAppDirInfo := NodeAppDirInfo(pkg.FilePath)
			if !nodeAppDirInfo.IsNodeAppDir {
				continue
			}

			key := nodeAppDirInfo.GetPackageKey(pkg)
			if lPkg, ok := lockFilePackages[key]; ok {
				pkg.Indirect = lPkg.Indirect
				pkg.RootDependencies = lPkg.RootDependencies
				pkg.DependsOn = lPkg.DependsOn

				result.Packages[j] = pkg
				matchFoundInNode[key] = struct{}{}
			}

		}

		results[i] = result
	}

	// Clean up lock file packages
	for i, result := range results {
		nodeAppDirInfo := NodeAppDirInfo(result.Target)
		if !nodeAppDirInfo.IsNodeLockFile {
			continue
		}

		// Remove packages that had corresponding match in Node.js target
		pkgs := lo.Filter(result.Packages, func(p ftypes.Package, i int) bool {
			key := nodeAppDirInfo.GetPackageKey(p)
			if _, ok := matchFoundInNode[key]; ok {
				return false
			}

			return true
		})

		result.Packages = pkgs
		results[i] = result
	}

	return results
}

type nodeAppDirInfo struct {
	Path           string
	FileName       string
	AppDir         string
	IsNodeAppDir   bool
	IsNodeLockFile bool
}

func NodeAppDirInfo(path string) nodeAppDirInfo {
	fileName := filepath.Base(path)
	isNodeAppDir := false
	isNodeLockFile := false

	if fileName == ftypes.NpmPkg {
		isNodeAppDir = true
	} else if lo.IndexOf(ftypes.NodeLockFiles, fileName) != -1 {
		isNodeAppDir = true
		isNodeLockFile = true

	} else {
		return nodeAppDirInfo{Path: path}
	}

	appDir := strings.Split(filepath.Dir(path), "node_modules")[0]

	// When path is empty filepath.Dir will return "."
	if appDir == "." {
		appDir = ""
	}

	return nodeAppDirInfo{
		Path:           path,
		FileName:       fileName,
		AppDir:         appDir,
		IsNodeAppDir:   isNodeAppDir,
		IsNodeLockFile: isNodeLockFile,
	}
}

func (n nodeAppDirInfo) GetPackageKey(pkg ftypes.Package) string {
	return fmt.Sprintf("%s:%s", n.AppDir, pkg.ID)
}
