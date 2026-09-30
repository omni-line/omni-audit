package npm_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/omni-line/omni-audit/internal/registry"
	regnpm "github.com/omni-line/omni-audit/internal/registry/npm"
)

func TestExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.EscapedPath() {
		case "/lodash":
			w.WriteHeader(http.StatusOK)
		case "/@acme%2Fmissing", "/missing-pkg":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)

	c := regnpm.New(registry.NewProber(srv.Client(), "omni-audit-test"))
	c.BaseURL = srv.URL

	cases := map[string]registry.Status{
		"lodash":        registry.Exists,
		"@acme/missing": registry.NotFound,
		"missing-pkg":   registry.NotFound,
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

	c := regnpm.New(registry.NewProber(srv.Client(), "test"))
	c.BaseURL = srv.URL

	// ".." would otherwise resolve to the registry root and return 200.
	for _, name := range []string{"..", ".hidden", "_private", "a/b", "@scope", "has space", ""} {
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
	for _, name := range []string{"lodash", "@types/node", "JSONStream", "left-pad", "a.b_c~d"} {
		if !regnpm.ValidName(name) {
			t.Errorf("%q should be valid", name)
		}
	}
}
