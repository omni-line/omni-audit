package mavencentral_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/registry/mavencentral"
)

func TestValidName(t *testing.T) {
	cases := map[string]bool{
		"com.google.guava:guava": true,
		"org.slf4j:slf4j-api":    true,
		"a:b":                    true,
		"Com.Example:Artifact":   true, // case-sensitive, still valid
		"":                       false,
		"guava":                  false,
		":guava":                 false,
		"com.google:":            false,
		"com.google:guava:extra": false,
		"com..google:guava":      false,
		".com.google:guava":      false,
		"com.google.:guava":      false,
		"com.google:gua va":      false,
		"com/google:guava":       false,
		"${g}:a":                 false,
	}
	for name, want := range cases {
		if got := mavencentral.ValidName(name); got != want {
			t.Errorf("ValidName(%q)=%v want %v", name, got, want)
		}
	}
}

func TestNormalizePreservesCase(t *testing.T) {
	got := mavencentral.Normalize("  Com.Example:Artifact  ")
	if got != "Com.Example:Artifact" {
		t.Fatalf("got %q", got)
	}
}

func TestPackageURL(t *testing.T) {
	got := mavencentral.PackageURL("com.google.guava:guava")
	want := "https://central.sonatype.com/artifact/com.google.guava/guava"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if mavencentral.PackageURL("not-a-coord") != "" {
		t.Fatal("invalid coord should yield empty PackageURL")
	}
}

func TestExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/com/google/guava/guava/maven-metadata.xml":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<metadata></metadata>`))
		case "/com/example/missing-lib/maven-metadata.xml":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)

	c := mavencentral.New(registry.NewProber(srv.Client(), "test"))
	c.BaseURL = srv.URL

	st, err := c.Exists(context.Background(), "com.google.guava:guava")
	if err != nil || st != registry.Exists {
		t.Fatalf("guava: status=%v err=%v", st, err)
	}
	st, err = c.Exists(context.Background(), "com.example:missing-lib")
	if err != nil || st != registry.NotFound {
		t.Fatalf("missing: status=%v err=%v", st, err)
	}
}

func TestInvalidNamesNeverHitNetwork(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	c := mavencentral.New(registry.NewProber(srv.Client(), "test"))
	c.BaseURL = srv.URL

	for _, name := range []string{"", "guava", ":a", "a:", "a:b:c", "com..x:y", "a/b:c", "has space:x"} {
		st, err := c.Exists(context.Background(), name)
		if st != registry.Unknown || !errors.Is(err, registry.ErrInvalidName) {
			t.Errorf("%q: status=%v err=%v", name, st, err)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid names made %d requests", calls)
	}
}
