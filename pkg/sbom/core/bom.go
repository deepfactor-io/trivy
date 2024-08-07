package core

import (
	"sort"

	dtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/deepfactor-io/trivy/v3/pkg/digest"
	ftypes "github.com/deepfactor-io/trivy/v3/pkg/fanal/types"
)

const (
	TypeFilesystem     ComponentType = "filesystem"
	TypeRepository     ComponentType = "repository"
	TypeContainerImage ComponentType = "container_image"
	TypeVM             ComponentType = "vm"
	TypeApplication    ComponentType = "application"
	TypeLibrary        ComponentType = "library"
	TypeOS             ComponentType = "os"
	TypePlatform       ComponentType = "platform"

	// Metadata properties
	PropertySchemaVersion = "SchemaVersion"
	PropertyType          = "Type"
	PropertyClass         = "Class"

	// Image properties
	PropertySize       = "Size"
	PropertyImageID    = "ImageID"
	PropertyRepoDigest = "RepoDigest"
	PropertyDiffID     = "DiffID"
	PropertyRepoTag    = "RepoTag"

	// Package properties
	PropertyPkgID           = "PkgID"
	PropertyPkgType         = "PkgType"
	PropertySrcName         = "SrcName"
	PropertySrcVersion      = "SrcVersion"
	PropertySrcRelease      = "SrcRelease"
	PropertySrcEpoch        = "SrcEpoch"
	PropertyModularitylabel = "Modularitylabel"
	PropertyFilePath        = "FilePath"
	PropertyLayerDigest     = "LayerDigest"
	PropertyLayerDiffID     = "LayerDiffID"

	// Relationships
	RelationshipDescribes RelationshipType = "describes"
	RelationshipContains  RelationshipType = "contains"
	RelationshipDependsOn RelationshipType = "depends_on"
)

type ComponentType string
type RelationshipType string

// BOM represents an intermediate representation of a component for SBOM.
type BOM struct {
	SerialNumber string
	Version      int

	rootID        string
	components    map[string]*Component
	relationships map[string][]Relationship

	// Vulnerabilities is a list of vulnerabilities that affect the component.
	// CycloneDX: vulnerabilities
	// SPDX: N/A
	vulnerabilities map[string][]Vulnerability

	// purls is a map of package URLs to UUIDs
	// This is used to ensure that each package URL is only represented once in the BOM.
	purls map[string][]string

	// parents is a map of parent components to their children
	// This field is populated when Options.Parents is set to true.
	parents map[string][]string

	// opts is a set of options for the BOM.
	opts Options
}

type Component struct {
	// id is the unique identifier of the component for internal use.
	// UUID results in inconsistent reports hence we use the hash (UID)
	id string

	// Type is the type of the component
	// CycloneDX: component.type
	Type ComponentType

	// Root represents the root of the BOM
	// Only one root is allowed in a BOM.
	// CycloneDX: metadata.component
	Root bool

	// Name is the name of the component
	// CycloneDX: component.name
	// SPDX: package.name
	Name string

	// Group is the group of the component
	// CycloneDX: component.group
	// SPDX: N/A
	Group string

	// Version is the version of the component
	// CycloneDX: component.version
	// SPDX: package.versionInfo
	Version string

	// SrcName is the name of the source component
	// CycloneDX: N/A
	// SPDX: package.sourceInfo
	SrcName string

	// SrcVersion is the version of the source component
	// CycloneDX: N/A
	// SPDX: package.sourceInfo
	SrcVersion string

	// SrcFile is the file path where the component is found.
	// CycloneDX: N/A
	// SPDX: package.sourceInfo
	SrcFile string

	// Licenses is a list of licenses that apply to the component
	// CycloneDX: component.licenses
	// SPDX: package.licenseConcluded, package.licenseDeclared
	Licenses []string

	// PkgIdentifier has PURL and BOMRef for the component
	// PURL:
	//   CycloneDX: component.purl
	//   SPDX: package.externalRefs.referenceLocator
	// BOMRef:
	//   CycloneDX: component.bom-ref
	//   SPDX: N/A
	PkgIdentifier ftypes.PkgIdentifier

	// Supplier is the name of the supplier of the component
	// CycloneDX: component.supplier
	// SPDX: package.supplier
	Supplier string

	// Files is a list of files that are part of the component.
	// CycloneDX: component.properties
	// SPDX: files
	Files []File

	// Properties is a list of key-value pairs that provide additional information about the component
	// CycloneDX: component.properties
	// SPDX: package.attributionTexts
	Properties Properties `hash:"set"`
}

func (c *Component) ID() string {
	return c.id
}

type File struct {
	// Path is a path of the file.
	// CycloneDX: N/A
	// SPDX: package.files[].fileName
	Path string

	// Hash is a hash that uniquely identify the component.
	// A file can have several digests with different algorithms, like SHA1, SHA256, etc.
	// CycloneDX: component.hashes
	// SPDX: package.files[].checksums
	Digests []digest.Digest
}

type Property struct {
	Name      string
	Value     string
	Namespace string
}

type Properties []Property

func (p Properties) Len() int { return len(p) }
func (p Properties) Less(i, j int) bool {
	if p[i].Name != p[j].Name {
		return p[i].Name < p[j].Name
	}
	return p[i].Value < p[j].Value
}
func (p Properties) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

type Relationship struct {
	Dependency string
	Type       RelationshipType
}

type Vulnerability struct {
	dtypes.Vulnerability
	ID               string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	PrimaryURL       string
	DataSource       *dtypes.DataSource
}

type Options struct {
	GenerateBOMRef bool // Generate BOMRef for CycloneDX
	Parents        bool // Hold parent maps
}

func NewBOM(opts Options) *BOM {
	return &BOM{
		components:      make(map[string]*Component),
		relationships:   make(map[string][]Relationship),
		vulnerabilities: make(map[string][]Vulnerability),
		purls:           make(map[string][]string),
		parents:         make(map[string][]string),
		opts:            opts,
	}
}

func (b *BOM) setupComponent(c *Component) {
	if c.id == "" {
		c.id = c.PkgIdentifier.UID
	}
	if c.PkgIdentifier.PURL != nil {
		p := c.PkgIdentifier.PURL.String()
		b.purls[p] = append(b.purls[p], c.PkgIdentifier.UID)
	}
	sort.Sort(c.Properties)
}

func (b *BOM) AddComponent(c *Component) {
	b.setupComponent(c)
	if c.Root {
		b.rootID = c.id
	}
	b.components[c.id] = c
}

func (b *BOM) AddRelationship(parent, child *Component, relationshipType RelationshipType) {
	// Check the wrong parent to avoid `panic`
	if parent == nil {
		return
	}
	if parent.id == "" {
		b.AddComponent(parent)
	}

	if child == nil {
		// It is possible that `relationships` already contains this parent.
		// Check this to avoid overwriting.
		if _, ok := b.relationships[parent.id]; !ok {
			b.relationships[parent.id] = nil // Meaning no dependencies
		}
		return
	}

	if child.id == "" {
		b.AddComponent(child)
	}

	b.relationships[parent.id] = append(b.relationships[parent.id], Relationship{
		Type:       relationshipType,
		Dependency: child.id,
	})

	if b.opts.Parents {
		b.parents[child.id] = append(b.parents[child.id], parent.id)
	}
}

func (b *BOM) AddVulnerabilities(c *Component, vulns []Vulnerability) {
	if c.id == "" {
		b.AddComponent(c)
	}
	if _, ok := b.vulnerabilities[c.id]; ok {
		return
	}
	b.vulnerabilities[c.id] = vulns
}

func (b *BOM) Root() *Component {
	root, ok := b.components[b.rootID]
	if !ok {
		return nil
	}
	if b.opts.GenerateBOMRef {
		root.PkgIdentifier.BOMRef = b.bomRef(root)
	}
	return root
}

func (b *BOM) Components() map[string]*Component {
	// Fill in BOMRefs for components
	if b.opts.GenerateBOMRef {
		for id, c := range b.components {
			b.components[id].PkgIdentifier.BOMRef = b.bomRef(c)
		}
	}
	return b.components
}

func (b *BOM) Relationships() map[string][]Relationship {
	return b.relationships
}

func (b *BOM) Vulnerabilities() map[string][]Vulnerability {
	return b.vulnerabilities
}

func (b *BOM) Parents() map[string][]string {
	return b.parents
}

// bomRef returns BOMRef for CycloneDX
// When multiple lock files have the same dependency with the same name and version, PURL in the BOM can conflict.
// In that case, PURL cannot be used as a unique identifier, and UUIDv4 be used for BOMRef.
func (b *BOM) bomRef(c *Component) string {
	if c.PkgIdentifier.BOMRef != "" {
		return c.PkgIdentifier.BOMRef
	}
	// Return the UUID of the component if the PURL is not present.
	if c.PkgIdentifier.PURL == nil {
		return c.id
	}
	p := c.PkgIdentifier.PURL.String()

	// Return the UUID of the component if the PURL is not unique in the BOM.
	if len(b.purls[p]) > 1 {
		return c.id
	}
	return p
}
