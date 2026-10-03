package dockerhub_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/registry/dockerhub"
)

func TestExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/repositories/library/nginx/":
			w.WriteHeader(http.StatusOK)
		case "/v2/repositories/bitnami/missing/":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)

	c := dockerhub.New(registry.NewProber(srv.Client(), "omni-audit-test"))
	c.BaseURL = srv.URL

	cases := map[string]registry.Status{
		"library/nginx":   registry.Exists,
		"bitnami/missing": registry.NotFound,
		"Library/Nginx":   registry.Exists,
	}
	for name, want := range cases {
		st, err := c.Exists(context.Background(), name)
		if err != nil || st != want {
			t.Errorf("%s: status=%v err=%v want %v", name, st, err, want)
		}
	}
}

func TestInvalidNamesNeverHitNetwork(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	c := dockerhub.New(registry.NewProber(srv.Client(), "test"))
	c.BaseURL = srv.URL

	for _, name := range []string{"", "nginx", "a/b/c", "../x", "has space/x", "/nope", "a/", "-bad/name"} {
		st, err := c.Exists(context.Background(), name)
		if st != registry.Unknown || !errors.Is(err, registry.ErrInvalidName) {
			t.Errorf("%q: status=%v err=%v", name, st, err)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid names made %d requests", calls)
	}
}

func TestValidName(t *testing.T) {
	for _, name := range []string{"library/nginx", "bitnami/nginx", "my-org/my_app.1"} {
		if !dockerhub.ValidName(name) {
			t.Errorf("%q should be valid", name)
		}
	}
	for _, name := range []string{"nginx", "a/b/c", "", "-bad/name", "has space/x"} {
		if dockerhub.ValidName(name) {
			t.Errorf("%q should be invalid", name)
		}
	}
}

func TestPackageURL(t *testing.T) {
	got := dockerhub.PackageURL("Library/Nginx")
	want := "https://hub.docker.com/r/library/nginx"
	if got != want {
		t.Fatalf("PackageURL=%q want %q", got, want)
	}
}
