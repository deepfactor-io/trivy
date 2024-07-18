package fsutils

import (
	"io"
	"io/fs"
	"log/slog"
	"math"
	"path"
	"path/filepath"
	"strings"
	"sync"

	licenseutils "github.com/deepfactor-io/trivy/pkg/fanal/analyzer/licensing"
	"github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/licensing"
	"github.com/deepfactor-io/trivy/pkg/log"
	xio "github.com/deepfactor-io/trivy/pkg/x/io"
	"golang.org/x/xerrors"
)

type RecursiveWalker struct {
	RecursiveWalkerInput

	// internal fields
	licenses    map[string][]types.License
	pkgIDMap    *sync.Map
	processChan chan licensing.ClassifierInput
	resultChan  chan licenseResult
	doneChan    chan struct{}
	waitGroup   sync.WaitGroup
}

type RecursiveWalkerInput struct {
	Logger                    *slog.Logger
	Parser                    types.PackageManifestParser
	PackageManifestFile       string
	PackageDependencyDir      string
	ClassifierConfidenceLevel float64
	LicenseTextCacheDir       string
	ParallelWorkers           int
}

type licenseResult struct {
	PkgID    string
	Licenses []types.License
}

// default constructor for Recursive walker
func NewRecursiveWalker(
	input RecursiveWalkerInput,
) (*RecursiveWalker, error) {
	return &RecursiveWalker{
		RecursiveWalkerInput: input,
		licenses:             make(map[string][]types.License),
		pkgIDMap:             &sync.Map{},

		processChan: make(chan licensing.ClassifierInput, 2*input.ParallelWorkers),
		resultChan:  make(chan licenseResult, 2*input.ParallelWorkers),
		doneChan:    make(chan struct{}, input.ParallelWorkers),
	}, nil
}

// starts the worker threads based on given number of workers
func (w *RecursiveWalker) StartWorkerPool() {
	for i := 0; i < w.ParallelWorkers; i++ {
		w.waitGroup.Add(1)
		go w.StartWorker()
	}

	// start the result thread to consume the license results and populate Licenses Map
	go w.processResults()
}

// stops the worker threads and closes their respective channels
func (w *RecursiveWalker) StopWorkerPool() {
	// trigger the done chan to stop all the go routines
	for i := 0; i < w.ParallelWorkers; i++ {
		w.doneChan <- struct{}{}
	}

	// wait for all threads to finish
	w.waitGroup.Wait()

	// stops the processResult thread
	close(w.resultChan)
}

// starts individual worker thread. Lists on Process channel and sends data to license classifier
func (w *RecursiveWalker) StartWorker() {
	defer w.waitGroup.Done()

	for {
		select {
		case <-w.doneChan:
			return

		case classifierInput, ok := <-w.processChan:
			if !ok {
				w.Logger.Debug("processChan is closed, exiting worker thread...")
				return
			}

			pkgID := classifierInput.PkgID
			concludedLicenses, err := checkForConcludedLicenses(classifierInput)
			if err != nil {
				w.Logger.Error("failed to get concluded licenses",
					log.Any("input", classifierInput), log.String("error", err.Error()))
			}
			if len(concludedLicenses) > 0 {
				w.Logger.Debug("Found concluded licenses",
					log.String("pkgID", pkgID), log.Any("concludedLicenses", concludedLicenses))
				w.resultChan <- licenseResult{PkgID: pkgID, Licenses: concludedLicenses}
			}
		}
	}
}

// Recursive walker walks the given fs and gets the concluded licenses.
// It's Used for deep license scanning.
// Note: For root as ".", we scan all the files and add them as loose licenses
func (w *RecursiveWalker) Walk(fsys fs.FS, root string, parentPkgID string) (bool, error) {
	if isSpecialPath(root) {
		return w.handleSpecialPath(fsys, root)
	}

	pkgID, err := w.processPackageManifest(fsys, root, parentPkgID)
	if err != nil {
		return false, err
	}

	// If package was already found in the scan, we skip it from license scanning
	// else we store it in pkgIDMap
	if pkgID != types.LOOSE_LICENSES {
		if _, present := w.pkgIDMap.Load(pkgID); present {
			w.Logger.Debug("pkgID is already present, skipping recursive walk",
				log.String("pkgID", pkgID), log.String("path", root))
			return true, nil
		} else {
			w.pkgIDMap.Store(pkgID, struct{}{})
		}
	}

	required := func(filePath string, d fs.DirEntry) bool {
		// Skip PkgDependency Dir (Ex: node_modules) directory and for Package manifest file
		pkgDependencyDir := path.Join(root, w.PackageDependencyDir)
		return !strings.HasPrefix(filePath, pkgDependencyDir) && !d.IsDir() && filePath != path.Join(root, w.PackageManifestFile)
	}

	classifier := func(path string, d fs.DirEntry, r io.Reader) error {
		file, ok := r.(xio.ReadSeekerAt)
		if !ok {
			return xerrors.Errorf("type assertion error, filepath: %s", path)
		}
		if readable, err := licenseutils.IsHumanReadable(file, math.MaxInt); err != nil || !readable {
			return nil
		}

		content, err := io.ReadAll(file)
		if err != nil {
			return xerrors.Errorf("unable to read file content; %q: %w", path, err)
		}

		w.processChan <- licensing.ClassifierInput{
			PkgID:               pkgID,
			FilePath:            path,
			Content:             content,
			ConfidenceLevel:     w.ClassifierConfidenceLevel,
			LicenseTextCacheDir: w.LicenseTextCacheDir,
			LicenseScanWorkers:  w.ParallelWorkers,
		}
		return nil
	}

	// Walk through every file present in given directory except dependency dir and manifest file
	if err := WalkDir(fsys, root, required, classifier); err != nil {
		w.Logger.Error("walkDir utils has failed", log.String("root", root), log.String("error", err.Error()))
	}

	foundPackageDependencyDir := checkPackageDependencyDir(fsys, root, w.PackageDependencyDir)
	if foundPackageDependencyDir {
		return w.handlePackageDependencies(fsys, root, pkgID)
	}

	return true, nil
}

// For special packages (like scoped packages in npm), we need to recurse further for scanning
func (w *RecursiveWalker) handleSpecialPath(fsys fs.FS, root string) (bool, error) {
	dirEntries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return false, xerrors.Errorf("failed to read dir contents: %w", err)
	}

	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			dependencyPath := path.Join(root, dirEntry.Name())
			if ret, err := w.Walk(fsys, dependencyPath, ""); !ret || err != nil {
				w.Logger.Error("Recursive walker has failed", log.String("path", dependencyPath))
			}
		}
	}
	return true, nil
}

// parses the package manifest file if present and valid. generates declared license
func (w *RecursiveWalker) processPackageManifest(fsys fs.FS, root, parentPkgID string) (string, error) {
	packageManifestPath := path.Join(root, w.PackageManifestFile)

	if root != "." && w.PackageManifestFile != "" {
		// check if package Manifest file exists, if yes, then parse then we parse it
		if f, err := fs.Stat(fsys, packageManifestPath); err == nil && f.Size() != 0 {
			pkg, err := w.Parser.ParseManifest(fsys, packageManifestPath)
			if err != nil {
				return "", xerrors.Errorf("unable to parse package manifest: %w", err)
			}

			w.Logger.Debug("Found declared licenses", log.String("pkgID", pkg.PackageID()),
				log.Any("declaredLicenses", pkg.DeclaredLicenses()))
			var declaredLicenses []types.License
			for _, license := range pkg.DeclaredLicenses() {
				declaredLicenses = append(declaredLicenses, types.License{Name: license, IsDeclared: true})
			}
			w.resultChan <- licenseResult{
				PkgID:    pkg.PackageID(),
				Licenses: declaredLicenses,
			}
			return pkg.PackageID(), nil
		}
	}

	var pkgID string
	if parentPkgID == "" {
		w.Logger.Debug("Parent PkgID is empty. Adding to loose licenses", log.String("path", root))
		pkgID = types.LOOSE_LICENSES
	} else {
		w.Logger.Debug("Found Parent Pkg ID, using it", log.String("path", root),
			log.String("parent PkgID", parentPkgID))
		pkgID = parentPkgID
	}

	return pkgID, nil
}

// checks whether given package dependency dir is present in given fs or not
func checkPackageDependencyDir(fsys fs.FS, root, packageDependencyDir string) bool {
	if root != "." && packageDependencyDir != "" {
		if _, err := fs.Stat(fsys, path.Join(root, packageDependencyDir)); err == nil {
			return true
		}
	}
	return false
}

// applies license classifier for given input and gets concluded licenses
func checkForConcludedLicenses(
	classiferInput licensing.ClassifierInput,
) ([]types.License, error) {
	var concludedLicenses []types.License

	lf, err := classiferInput.Classify()
	if err != nil {
		return concludedLicenses, err
	}

	for _, finding := range lf.Findings {
		concludedLicenses = append(concludedLicenses, types.License{
			Name:          finding.Name,
			Type:          lf.Type,
			IsDeclared:    false,
			LicenseText:   finding.LicenseText,
			CopyrightText: finding.CopyRightText,
			FilePath:      lf.FilePath,
			Findings:      lf.Findings,
		})
	}

	return concludedLicenses, nil
}

// recurse further if dependency dir is present in given root path
func (w *RecursiveWalker) handlePackageDependencies(fsys fs.FS, root string, pkgID string) (bool, error) {
	dirEntries, err := fs.ReadDir(fsys, path.Join(root, w.PackageDependencyDir))
	if err != nil {
		return false, xerrors.Errorf("failed to read dir contents: %w", err)
	}

	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			dependencyPath := path.Join(root, w.PackageDependencyDir, dirEntry.Name())
			if ret, err := w.Walk(fsys, dependencyPath, pkgID); !ret || err != nil {
				w.Logger.Error("Recursive walker has failed", log.String("path", dependencyPath))
			}
		}
	}
	return true, nil
}

// ex: for node it's scoped packages
func isSpecialPath(path string) bool {
	return strings.HasPrefix(filepath.Base(path), "@")
}

// Process Results consumes the recursive walker's result channel and populates the licenses map
func (w *RecursiveWalker) processResults() {
	for result := range w.resultChan {
		w.licenses[result.PkgID] = append(w.licenses[result.PkgID], result.Licenses...)
	}
}

// returns the license map after processing
func (w *RecursiveWalker) GetLicenses() map[string][]types.License {
	w.waitGroup.Wait()
	return w.licenses
}
