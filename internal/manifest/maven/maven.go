// Package maven parses pom.xml dependency declarations.
package maven

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
)

// Groups are the pom.xml sections scanned, in reporting order.
var Groups = []string{"dependencies", "dependencyManagement"}

// xmlnsRe strips XML namespace declarations so encoding/xml can match local names.
var xmlnsRe = regexp.MustCompile(`\sxmlns(?::\w+)?="[^"]*"`)

type pomProject struct {
	XMLName              xml.Name      `xml:"project"`
	GroupID              string        `xml:"groupId"`
	ArtifactID           string        `xml:"artifactId"`
	Version              string        `xml:"version"`
	Parent               pomParent     `xml:"parent"`
	Properties           pomProperties `xml:"properties"`
	Dependencies         pomDeps       `xml:"dependencies"`
	DependencyManagement pomDepMgmt    `xml:"dependencyManagement"`
}

type pomParent struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type pomProperties struct {
	Entries []pomProperty `xml:",any"`
}

type pomProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type pomDeps struct {
	Dependencies []pomDependency `xml:"dependency"`
}

type pomDepMgmt struct {
	Dependencies pomDeps `xml:"dependencies"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// Parse returns Maven-coordinate dependencies from pom.xml bytes.
//
// Names are groupId:artifactId. Dependencies missing groupId inherit the
// project (or parent) groupId. Simple ${project.*} and <properties> values
// are resolved for groupId/artifactId; unresolved placeholders are skipped.
// Version is kept verbatim. Deduplicates by groupId:artifactId.
func Parse(data []byte) ([]manifest.Dependency, error) {
	cleaned := xmlnsRe.ReplaceAll(data, nil)
	var proj pomProject
	if err := xml.Unmarshal(cleaned, &proj); err != nil {
		return nil, fmt.Errorf("parse pom.xml: %w", err)
	}

	projectGroup := strings.TrimSpace(proj.GroupID)
	if projectGroup == "" {
		projectGroup = strings.TrimSpace(proj.Parent.GroupID)
	}
	projectArtifact := strings.TrimSpace(proj.ArtifactID)
	projectVersion := strings.TrimSpace(proj.Version)
	if projectVersion == "" {
		projectVersion = strings.TrimSpace(proj.Parent.Version)
	}

	props := map[string]string{
		"project.groupId":    projectGroup,
		"project.artifactId": projectArtifact,
		"project.version":    projectVersion,
	}
	for _, e := range proj.Properties.Entries {
		key := e.XMLName.Local
		if key == "" {
			continue
		}
		props[key] = strings.TrimSpace(e.Value)
	}
	// Resolve project.* against the raw project fields first, then re-apply
	// so ${project.groupId} in a property value can expand.
	projectGroup = resolveProps(projectGroup, props)
	projectArtifact = resolveProps(projectArtifact, props)
	projectVersion = resolveProps(projectVersion, props)
	props["project.groupId"] = projectGroup
	props["project.artifactId"] = projectArtifact
	props["project.version"] = projectVersion

	seen := make(map[string]struct{})
	var out []manifest.Dependency

	sections := []struct {
		group string
		deps  []pomDependency
	}{
		{"dependencies", proj.Dependencies.Dependencies},
		{"dependencyManagement", proj.DependencyManagement.Dependencies.Dependencies},
	}
	for _, sec := range sections {
		for _, dep := range sec.deps {
			groupID := strings.TrimSpace(dep.GroupID)
			if groupID == "" {
				groupID = projectGroup
			}
			artifactID := strings.TrimSpace(dep.ArtifactID)
			groupID = resolveProps(groupID, props)
			artifactID = resolveProps(artifactID, props)
			if groupID == "" || artifactID == "" {
				continue
			}
			if hasPlaceholder(groupID) || hasPlaceholder(artifactID) {
				continue
			}
			name := groupID + ":" + artifactID
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, manifest.Dependency{
				Name:    name,
				Version: strings.TrimSpace(dep.Version),
				Group:   sec.group,
				Line:    artifactLine(data, artifactID),
			})
		}
	}
	if out == nil {
		out = []manifest.Dependency{}
	}
	return out, nil
}

var propRefRe = regexp.MustCompile(`\$\{([^}]+)\}`)

func resolveProps(s string, props map[string]string) string {
	if s == "" || !strings.Contains(s, "${") {
		return s
	}
	// Bound iterations so cyclic property references cannot loop forever.
	for i := 0; i < 10 && strings.Contains(s, "${"); i++ {
		next := propRefRe.ReplaceAllStringFunc(s, func(m string) string {
			key := m[2 : len(m)-1]
			if v, ok := props[key]; ok {
				return v
			}
			return m
		})
		if next == s {
			break
		}
		s = next
	}
	return s
}

func hasPlaceholder(s string) bool {
	return strings.Contains(s, "${")
}

func artifactLine(data []byte, artifactID string) int {
	if artifactID == "" {
		return 0
	}
	needle := []byte("<artifactId>" + artifactID + "</artifactId>")
	off := bytes.Index(data, needle)
	if off < 0 {
		// Namespace-stripped or spaced variants: fall back to the bare id.
		off = bytes.Index(data, []byte(artifactID))
		if off < 0 {
			return 0
		}
	}
	return manifest.LineAt(data, off)
}

// Normalize lowercases groupId:artifactId.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// Split returns groupId and artifactId.
func Split(name string) (namespace, leaf string) {
	name = Normalize(name)
	i := strings.IndexByte(name, ':')
	if i <= 0 || i == len(name)-1 {
		return "", name
	}
	return name[:i], name[i+1:]
}
