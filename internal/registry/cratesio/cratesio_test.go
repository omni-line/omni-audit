package cratesio_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/registry/cratesio"
)

func TestNormalize(t *testing.T) {
	if got := cratesio.Normalize("  SerDe  "); got != "serde" {
		t.Fatalf("got %q", got)
	}
}

func TestValidName(t *testing.T) {
	cases := map[string]bool{
		"serde":                 true,
		"serde_json":            true,
		"foo-bar":               true,
		"A":                     true,
		"a1":                    true,
		"":                      false,
		"1abc":                  false,
		"-abc":                  false,
		"_abc":                  false,
		"foo.bar":               false,
		"foo/bar":               false,
		"föö":                   false,
		strings.Repeat("a", 64): true,
		strings.Repeat("a", 65): false,
	}
	for name, want := range cases {
		if got := cratesio.ValidName(name); got != want {
			t.Errorf("ValidName(%q)=%v want %v", name, got, want)
		}
	}
}

func TestExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/crates/serde":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/crates/acme-private":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)

	c := cratesio.New(registry.NewProber(srv.Client(), "omni-audit-test"))
	c.BaseURL = srv.URL

	st, err := c.Exists(context.Background(), "SerDe")
	if err != nil || st != registry.Exists {
		t.Fatalf("serde: status=%v err=%v", st, err)
	}
	st, err = c.Exists(context.Background(), "acme-private")
	if err != nil || st != registry.NotFound {
		t.Fatalf("acme-private: status=%v err=%v", st, err)
	}
}

func TestInvalidNames(t *testing.T) {
	c := cratesio.New(registry.NewProber(nil, "test"))
	c.BaseURL = "http://127.0.0.1:0"
	for _, name := range []string{"", "1abc", "-x", "foo.bar", "../etc", strings.Repeat("a", 65)} {
		st, err := c.Exists(context.Background(), name)
		if st != registry.Unknown || !errors.Is(err, registry.ErrInvalidName) {
			t.Errorf("%q: status=%v err=%v", name, st, err)
		}
	}
}

func TestPackageURL(t *testing.T) {
	if got := cratesio.PackageURL("SerDe"); got != "https://crates.io/crates/serde" {
		t.Fatalf("got %q", got)
	}
}
