package ecosystem

import (
	"path"
	"strings"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/manifest/docker"
	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/registry/dockerhub"
)

// Docker is Dockerfile / Compose image refs checked against Docker Hub.
func Docker(c registry.Checker) Ecosystem {
	return Ecosystem{
		Name:       "docker",
		Registry:   "hub.docker.com",
		IsManifest: isDockerManifest,
		Parse:      parseDockerManifest,
		Normalize:  dockerhub.Normalize,
		PackageURL: dockerhub.PackageURL,
		Remediation: "Use a private registry hostname for internal images, claim the Docker Hub " +
			"namespace/repo, and prefer digest pins.",
		Checker: c,
	}
}

func isDockerManifest(rel string) bool {
	base := path.Base(rel)
	lower := strings.ToLower(base)
	switch lower {
	case "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml":
		return true
	}
	if lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") {
		return true
	}
	return false
}

func parseDockerManifest(rel string, data []byte) ([]manifest.Dependency, error) {
	base := strings.ToLower(path.Base(rel))
	switch base {
	case "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml":
		return docker.ParseCompose(data)
	default:
		return docker.ParseDockerfile(data)
	}
}
