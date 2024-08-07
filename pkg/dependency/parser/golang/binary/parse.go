package binary

import (
	"bytes"
	"cmp"
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"io"
	"runtime/debug"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/pflag"
	"golang.org/x/mod/semver"
	"golang.org/x/xerrors"

	ftypes "github.com/deepfactor-io/trivy/v3/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/v3/pkg/log"
	xio "github.com/deepfactor-io/trivy/v3/pkg/x/io"
)

var (
	ErrUnrecognizedExe     = xerrors.New("unrecognized executable format")
	ErrNonGoBinary         = xerrors.New("non go binary")
	readSize               = 32 * 1024
	elfPrefix              = []byte("\x7fELF")
	elfGoNote              = []byte("Go\x00\x00")
	elfGNUNote             = []byte("GNU\x00")
	errProgramNotSupported = fmt.Errorf("Program not supported")
	errBuildIDNotFound     = fmt.Errorf("Go BuildID not found")
)

const offsetToNoteData = 16
const offsetToNoteFields = 12
const sizeOfNoteNameAndValue = 4
const elfGoBuildIDTag = 4
const gnuBuildIDTag = 3

// convertError detects buildinfo.errUnrecognizedFormat and convert to
// ErrUnrecognizedExe and convert buildinfo.errNotGoExe to ErrNonGoBinary
func convertError(err error) error {
	errText := err.Error()
	if strings.HasSuffix(errText, "unrecognized file format") {
		return ErrUnrecognizedExe
	}
	if strings.HasSuffix(errText, "not a Go executable") {
		return ErrNonGoBinary
	}

	return err
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("gobinary"),
	}
}

// Parse scans file to try to report the Go and module versions.
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var warnings []string
	var buildID string

	info, err := buildinfo.Read(r)
	if err != nil {
		return nil, nil, convertError(err)
	}

	if len(info.Deps) > 0 {
		// get build id
		buildID, err = getBuildID(r)
		if err != nil {
			warnings = []string{err.Error()}
		}
	}

	// Ex: "go1.22.3 X:boringcrypto"
	stdlibVersion := strings.TrimPrefix(info.GoVersion, "go")
	stdlibVersion, _, _ = strings.Cut(stdlibVersion, " ")

	ldflags := p.ldFlags(info.Settings)
	pkgs := make(ftypes.Packages, 0, len(info.Deps)+2)
	pkgs = append(pkgs, ftypes.Package{
		// Add the Go version used to build this binary.
		Name:         "stdlib",
		Version:      stdlibVersion,
		Relationship: ftypes.RelationshipDirect, // Considered a direct dependency as the main module depends on the standard packages.
	})

	// There are times when gobinaries don't contain Main information.
	// e.g. `Go` binaries (e.g. `go`, `gofmt`, etc.)
	if info.Main.Path != "" {
		pkgs = append(pkgs, ftypes.Package{
			// Add main module
			Name: info.Main.Path,
			// Only binaries installed with `go install` contain semver version of the main module.
			// Other binaries use the `(devel)` version, but still may contain a stamped version
			// set via `go build -ldflags='-X main.version=<semver>'`, so we fallback to this as.
			// as a secondary source.
			// See https://github.com/deepfactor-io/trivy/issues/1837#issuecomment-1832523477.
			Version:      cmp.Or(p.checkVersion(info.Main.Path, info.Main.Version), p.ParseLDFlags(info.Main.Path, ldflags)),
			Relationship: ftypes.RelationshipRoot,
		})
	}

	for _, dep := range info.Deps {
		// binaries with old go version may incorrectly add module in Deps
		// In this case Path == "", Version == "Devel"
		// we need to skip this
		if dep.Path == "" {
			continue
		}

		mod := dep
		if dep.Replace != nil {
			mod = dep.Replace
		}

		pkgs = append(pkgs, ftypes.Package{
			Name:     mod.Path,
			Version:  p.checkVersion(mod.Path, mod.Version),
			BuildID:  buildID,
			Warnings: warnings,
		})
	}

	sort.Sort(pkgs)
	return pkgs, nil, nil
}

/**
 * The Go build ID is stored in a note described by an ELF PT_NOTE prog
 * header. The caller has already opened filename, to get f, and read
 * at least 4 kB out, in data.
 */
func readELF(r xio.ReadSeekerAt, data []byte) (buildid string, err error) {
	/*
	 * Assume the note content is in the data, already read.
	 * Rewrite the ELF header to set shoff and shnum to 0, so that we can pass
	 * the data to elf.NewFile and it will decode the Prog list but not
	 * try to read the section headers and the string table from disk.
	 * That's a waste of I/O when all we care about is the Prog list
	 * and the one ELF note.
	 * These specific bytes are at offsets 40-43, 44-47, 60, and 61 in the data
	 * slice.
	 */
	switch elf.Class(data[elf.EI_CLASS]) {
	case elf.ELFCLASS32:
		return "", errProgramNotSupported
	case elf.ELFCLASS64:
		data[40], data[41], data[42], data[43] = 0, 0, 0, 0
		data[44], data[45], data[46], data[47] = 0, 0, 0, 0
		data[60] = 0
		data[61] = 0
	}
	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	var gnu string
	for _, p := range ef.Progs {
		if p.Type != elf.PT_NOTE || p.Filesz < offsetToNoteData {
			continue
		}
		var note []byte
		if p.Off+p.Filesz < uint64(len(data)) {
			note = data[p.Off : p.Off+p.Filesz]
		} else {
			/*
			 * For some linkers, such as the Solaris linker,
			 * the buildid may not be found in data (which
			 * likely contains the first 16kB of the file)
			 * or even the first few megabytes of the file
			 * due to differences in note segment placement;
			 * in that case, extract the note data manually.
			 */
			_, err = r.Seek(int64(p.Off), io.SeekStart)
			if err != nil {
				return "", err
			}
			note = make([]byte, p.Filesz)
			_, err = io.ReadFull(r, note)
			if err != nil {
				return "", err
			}
		}
		filesz := p.Filesz
		off := p.Off
		for filesz >= offsetToNoteData {
			nameSize := ef.ByteOrder.Uint32(note)
			valSize := ef.ByteOrder.Uint32(note[sizeOfNoteNameAndValue:])
			tag := ef.ByteOrder.Uint32(note[8:])
			nname := note[offsetToNoteFields : offsetToNoteFields+sizeOfNoteNameAndValue]
			if nameSize == sizeOfNoteNameAndValue && offsetToNoteData+valSize <= uint32(len(note)) &&
				tag == elfGoBuildIDTag && bytes.Equal(nname, elfGoNote) {
				return string(note[offsetToNoteData : offsetToNoteData+valSize]), nil
			}
			if nameSize == sizeOfNoteNameAndValue && offsetToNoteData+valSize <= uint32(len(note)) &&
				tag == gnuBuildIDTag && bytes.Equal(nname, elfGNUNote) {
				gnu = string(note[offsetToNoteData : offsetToNoteData+valSize])
			}
			nameSize = (nameSize + 3) &^ 3
			valSize = (valSize + 3) &^ 3
			notesz := uint64(offsetToNoteFields + nameSize + valSize)
			if filesz <= notesz {
				break
			}
			off += notesz
			align := p.Align
			if align != 0 {
				alignedOff := (off + align - 1) &^ (align - 1)
				notesz += alignedOff - off
				off = alignedOff
			}
			filesz -= notesz
			note = note[notesz:]
		}
	}
	/*
	 * If we didn't find a Go note, use a GNU note if available.
	 * This is what gccgo uses.
	 */
	if gnu != "" {
		return gnu, nil
	}
	/* No note. Treat as successful but build ID empty. */
	return "", nil
}

func getBuildID(r xio.ReadSeekerAt) (id string, err error) {
	/*
	 * Adding some sanity check
	 * we only support elf header
	 */

	buf := make([]byte, 8)
	if _, err := r.ReadAt(buf, 0); err != nil {
		return "", err
	}
	if string(buf) != "!<arch>\n" {
		if string(buf) == "<bigaf>\n" {
			return "", errProgramNotSupported
		}
		data := make([]byte, readSize)
		_, err = io.ReadFull(r, data)
		if err == io.ErrUnexpectedEOF {
			err = nil
		}
		if err != nil {
			return "", err
		}
		if bytes.HasPrefix(data, elfPrefix) {
			return readELF(r, data)
		}
	}
	return "", errProgramNotSupported
}

// checkVersion detects `(devel)` versions, removes them and adds a debug message about it.
func (p *Parser) checkVersion(name, version string) string {
	if version == "(devel)" {
		p.logger.Debug("Unable to detect main module's dependency version - `(devel)` is used", log.String("dependency", name))
		return ""
	}
	return version
}

func (p *Parser) ldFlags(settings []debug.BuildSetting) []string {
	for _, setting := range settings {
		if setting.Key != "-ldflags" {
			continue
		}

		return strings.Fields(setting.Value)
	}
	return nil
}

// ParseLDFlags attempts to parse the binary's version from any `-ldflags` passed to `go build` at build time.
func (p *Parser) ParseLDFlags(name string, flags []string) string {
	p.logger.Debug("Parsing dependency's build info settings", "dependency", name, "-ldflags", flags)
	fset := pflag.NewFlagSet("ldflags", pflag.ContinueOnError)
	// This prevents the flag set from erroring out if other flags were provided.
	// This helps keep the implementation small, so that only the -X flag is needed.
	fset.ParseErrorsWhitelist.UnknownFlags = true
	// The shorthand name is needed here because setting the full name
	// to `X` will cause the flag set to look for `--X` instead of `-X`.
	// The flag can also be set multiple times, so a string slice is needed
	// to handle that edge case.
	var x map[string]string
	fset.StringToStringVarP(&x, "", "X", nil, "")
	if err := fset.Parse(flags); err != nil {
		p.logger.Error("Could not parse -ldflags found in build info", log.Err(err))
		return ""
	}

	// foundVersions contains discovered versions by type.
	// foundVersions doesn't contain duplicates. Versions are filled into first corresponding category.
	// Possible elements(categories):
	//   [0]: Versions using format `github.com/<module_owner>/<module_name>/cmd/**/*.<version>=x.x.x`
	//   [1]: Versions that use prefixes from `defaultPrefixes`
	//   [2]: Other versions
	var foundVersions = make([][]string, 3)
	defaultPrefixes := []string{"main", "common", "version", "cmd"}
	for key, val := range x {
		// It's valid to set the -X flags with quotes so we trim any that might
		// have been provided: Ex:
		//
		// -X main.version=1.0.0
		// -X=main.version=1.0.0
		// -X 'main.version=1.0.0'
		// -X='main.version=1.0.0'
		// -X="main.version=1.0.0"
		// -X "main.version=1.0.0"
		key = strings.TrimLeft(key, `'`)
		val = strings.TrimRight(val, `'`)
		if isVersionXKey(key) && isValidSemVer(val) {
			switch {
			case strings.HasPrefix(key, name+"/cmd/"):
				foundVersions[0] = append(foundVersions[0], val)
			case slices.Contains(defaultPrefixes, strings.ToLower(versionPrefix(key))):
				foundVersions[1] = append(foundVersions[1], val)
			default:
				foundVersions[2] = append(foundVersions[2], val)
			}
		}
	}

	return p.chooseVersion(name, foundVersions)
}

// chooseVersion chooses version from found versions
// Categories order:
// module name with `cmd` => versions with default prefixes => other versions
// See more in https://github.com/deepfactor-io/trivy/issues/6702#issuecomment-2122271427
func (p *Parser) chooseVersion(moduleName string, vers [][]string) string {
	for _, versions := range vers {
		// Versions for this category was not found
		if len(versions) == 0 {
			continue
		}

		// More than 1 version for one category.
		// Use empty version.
		if len(versions) > 1 {
			p.logger.Debug("Unable to detect dependency version. `-ldflags` build info settings contain more than one version. Empty version used.", log.String("dependency", moduleName))
			return ""
		}
		return versions[0]
	}

	p.logger.Debug("Unable to detect dependency version. `-ldflags` build info settings don't contain version flag. Empty version used.", log.String("dependency", moduleName))
	return ""
}

func isVersionXKey(key string) bool {
	key = strings.ToLower(key)
	// The check for a 'ver' prefix enables the parser to pick up Trivy's own version value that's set.
	return strings.HasSuffix(key, ".version") || strings.HasSuffix(key, ".ver")
}

func isValidSemVer(ver string) bool {
	// semver.IsValid strictly checks for the v prefix so prepending 'v'
	// here and checking validity again increases the chances that we
	// parse a valid semver version.
	return semver.IsValid(ver) || semver.IsValid("v"+ver)
}

// versionPrefix returns version prefix from `-ldflags` flag key
// e.g.
//   - `github.com/deepfactor-io/trivy/pkg/version/app.ver` => `version`
//   - `github.com/google/go-containerregistry/cmd/crane/common.ver` => `common`
func versionPrefix(s string) string {
	// Trim module part.
	// e.g. `github.com/deepfactor-io/trivy/pkg/Version.version` => `Version.version`
	if lastIndex := strings.LastIndex(s, "/"); lastIndex > 0 {
		s = s[lastIndex+1:]
	}

	s, _, _ = strings.Cut(s, ".")
	return strings.ToLower(s)
}
