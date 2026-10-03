package conancenter_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/registry/conancenter"
)

func TestExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method=%s want GET", r.Method)
		}
		if r.URL.Path != "/v2/conans/search" {
			t.Errorf("path=%s", r.URL.Path)
		}
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		var results []string
		switch q {
		case "zlib":
			results = []string{"zlib/1.2.11@_/_", "zlib/1.2.13@_/_"}
		case "zlibx":
			// Looking up "zlib" must not treat a zlibx hit as Exists.
			results = []string{"zlibx/1.0.0@_/_"}
		case "missing":
			results = []string{}
		case "partial":
			// Search for an exact name that only appears as a prefix of another.
			results = []string{"zlibx/1.0.0@_/_", "zlibfoo/2.0@_/_"}
		default:
			results = nil
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	}))
	t.Cleanup(srv.Close)

	c := conancenter.New(registry.NewProber(srv.Client(), "omni-audit-test"))
	c.BaseURL = srv.URL

	cases := []struct {
		name string
		want registry.Status
	}{
		{"zlib", registry.Exists},
		{"Zlib", registry.Exists},
		{"missing", registry.NotFound},
		{"partial", registry.NotFound},
	}
	for _, tc := range cases {
		st, err := c.Exists(context.Background(), tc.name)
		if err != nil || st != tc.want {
			t.Errorf("%s: status=%v err=%v want %v", tc.name, st, err, tc.want)
		}
	}

	// Explicit partial-name case: query "zlib" but server returns only zlibx.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"results":["zlibx/1.0.0@_/_"]}`))
	}))
	t.Cleanup(srv2.Close)
	c2 := conancenter.New(registry.NewProber(srv2.Client(), "omni-audit-test"))
	c2.BaseURL = srv2.URL
	st, err := c2.Exists(context.Background(), "zlib")
	if err != nil || st != registry.NotFound {
		t.Fatalf("partial zlibx hit: status=%v err=%v want not_found", st, err)
	}
}

func TestExistsEmptyResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	t.Cleanup(srv.Close)

	c := conancenter.New(registry.NewProber(srv.Client(), "omni-audit-test"))
	c.BaseURL = srv.URL
	st, err := c.Exists(context.Background(), "unclaimed-pkg")
	if err != nil || st != registry.NotFound {
		t.Fatalf("status=%v err=%v want not_found", st, err)
	}
}

func TestInvalidNames(t *testing.T) {
	c := conancenter.New(registry.NewProber(nil, "test"))
	c.BaseURL = "http://127.0.0.1:0"
	for _, name := range []string{"", "A", "../etc", "pkg name", "-bad"} {
		st, err := c.Exists(context.Background(), name)
		if st != registry.Unknown || !errors.Is(err, registry.ErrInvalidName) {
			t.Errorf("%q: status=%v err=%v", name, st, err)
		}
	}
}

func TestPackageURL(t *testing.T) {
	got := conancenter.PackageURL("Zlib")
	want := "https://conan.io/center/recipes/zlib"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestValidName(t *testing.T) {
	for _, name := range []string{"zlib", "openssl", "foo_bar", "a.b", "x+y", "ab"} {
		if !conancenter.ValidName(name) {
			t.Errorf("%q should be valid", name)
		}
	}
	for _, name := range []string{"", "a", "-bad", ".bad", "Has Space"} {
		if conancenter.ValidName(name) {
			t.Errorf("%q should be invalid", name)
		}
	}
}
