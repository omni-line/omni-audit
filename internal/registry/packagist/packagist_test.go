package packagist_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/registry/packagist"
)

func TestExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/p2/monolog/monolog.json":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case "/p2/acme/private.json":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)

	c := packagist.New(srv.Client(), "omni-audit-test")
	c.BaseURL = srv.URL

	st, err := c.Exists(context.Background(), "monolog/monolog")
	if err != nil || st != registry.Exists {
		t.Fatalf("monolog: status=%v err=%v", st, err)
	}

	st, err = c.Exists(context.Background(), "Acme/Private")
	if err != nil || st != registry.NotFound {
		t.Fatalf("acme/private: status=%v err=%v", st, err)
	}
}
