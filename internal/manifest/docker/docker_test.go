package docker_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/manifest"
	"github.com/omni-line/omni-audit/internal/manifest/docker"
)

func TestParseDockerfile(t *testing.T) {
	data := []byte(`
# comment
FROM nginx:1.25 AS base
FROM --platform=linux/amd64 bitnami/nginx:latest
FROM --platform=$BUILDPLATFORM node:20 AS build
FROM scratch
FROM scratch AS empty
FROM ghcr.io/org/app:1
FROM docker.io/library/redis:7
FROM docker.io/bitnami/redis
FROM NGINX
FROM localhost:5000/private/app
`)
	deps, err := docker.ParseDockerfile(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]manifest.Dependency{}
	for _, d := range deps {
		got[d.Name] = d
		if d.Group != "FROM" {
			t.Errorf("%s: group=%q", d.Name, d.Group)
		}
	}
	want := []string{
		"library/nginx",
		"bitnami/nginx",
		"library/node",
		"library/redis",
		"bitnami/redis",
	}
	if len(deps) != len(want) {
		t.Fatalf("len=%d want %d: %#v", len(deps), len(want), deps)
	}
	for _, name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("missing %s in %#v", name, deps)
		}
	}
	if got["library/nginx"].Version != "1.25" {
		t.Errorf("nginx version=%q", got["library/nginx"].Version)
	}
	if got["library/nginx"].Line == 0 {
		t.Error("expected line for FROM nginx")
	}
	// Deduped: second NGINX / docker.io/library paths collapse.
	if _, ok := got["library/scratch"]; ok {
		t.Error("scratch must be skipped")
	}
	if _, ok := got["org/app"]; ok {
		t.Error("ghcr.io must be skipped")
	}
}

func TestParseCompose(t *testing.T) {
	data := []byte(`
services:
  web:
    image: nginx:1.25
  db:
    image: "bitnami/postgresql:16"
  skip_var:
    image: ${IMG}
  skip_dollar:
    image: $IMAGE
  mixed:
    image: redis:${TAG}
  other_reg:
    image: gcr.io/proj/img:1
  digest:
    image: alpine@sha256:deadbeef
  list:
    - image: 'library/busybox'
  commented: # not an image line
    build: .
`)
	deps, err := docker.ParseCompose(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range deps {
		got[d.Name] = d.Version
		if d.Group != "image" {
			t.Errorf("%s: group=%q", d.Name, d.Group)
		}
	}
	want := map[string]string{
		"library/nginx":      "1.25",
		"bitnami/postgresql": "16",
		"library/redis":      "${TAG}",
		"library/alpine":     "",
		"library/busybox":    "",
	}
	if len(deps) != len(want) {
		t.Fatalf("len=%d want %d: %#v", len(deps), len(want), deps)
	}
	for name, ver := range want {
		if got[name] != ver {
			t.Errorf("%s: version=%q want %q (all %#v)", name, got[name], ver, got)
		}
	}
}

func TestHubRepository(t *testing.T) {
	cases := []struct {
		in     string
		hub    string
		tag    string
		wantOK bool
	}{
		{"nginx", "library/nginx", "", true},
		{"nginx:1.25", "library/nginx", "1.25", true},
		{"bitnami/nginx:latest", "bitnami/nginx", "latest", true},
		{"nginx@sha256:abc", "library/nginx", "", true},
		{"docker.io/library/nginx", "library/nginx", "", true},
		{"docker.io/bitnami/nginx", "bitnami/nginx", "", true},
		{"DOCKER.IO/Library/Nginx:1", "library/nginx", "1", true},
		{"scratch", "", "", false},
		{"ghcr.io/foo/bar", "", "", false},
		{"gcr.io/x/y", "", "", false},
		{"localhost:5000/x", "", "", false},
		{"registry.example.com/x", "", "", false},
		{"${IMG}", "", "", false},
	}
	for _, tc := range cases {
		hub, tag, ok := docker.HubRepository(tc.in)
		if ok != tc.wantOK || hub != tc.hub || tag != tc.tag {
			t.Errorf("HubRepository(%q)=(%q,%q,%v) want (%q,%q,%v)",
				tc.in, hub, tag, ok, tc.hub, tc.tag, tc.wantOK)
		}
	}
}

func TestParseEmpty(t *testing.T) {
	deps, err := docker.ParseDockerfile([]byte("RUN echo hi\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 0 {
		t.Fatalf("want empty, got %#v", deps)
	}
}
