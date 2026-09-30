package packagist_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/registry/packagist"
)

func TestExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/p2/monolog/monolog.json", "/p2/acme/dev-only~dev.json":
			w.WriteHeader(http.StatusOK)
		case "/p2/acme/private.json", "/p2/acme/private~dev.json", "/p2/acme/dev-only.json":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)

	c := packagist.New(registry.NewProber(srv.Client(), "omni-audit-test"))
	c.BaseURL = srv.URL

	cases := map[string]registry.Status{
		"monolog/monolog": registry.Exists,
		"Acme/Private":    registry.NotFound,
		"acme/dev-only":   registry.Exists,
	}
	for name, want := range cases {
		st, err := c.Exists(context.Background(), name)
		if err != nil || st != want {
			t.Errorf("%s: status=%v err=%v want %v", name, st, err, want)
		}
	}
}

func TestInvalidNames(t *testing.T) {
	c := packagist.New(registry.NewProber(nil, "test"))
	c.BaseURL = "http://127.0.0.1:0"
	for _, name := range []string{"php", "ext-json", "../etc/passwd", "vendor/", "/pkg", "a/b/c"} {
		st, err := c.Exists(context.Background(), name)
		if st != registry.Unknown || !errors.Is(err, registry.ErrInvalidName) {
			t.Errorf("%q: status=%v err=%v", name, st, err)
		}
	}
}
