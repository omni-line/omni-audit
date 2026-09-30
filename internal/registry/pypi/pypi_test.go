package pypi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/omni-line/omni-audit/internal/registry"
	regpypi "github.com/omni-line/omni-audit/internal/registry/pypi"
)

func TestExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/requests/json":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case "/pypi/acme-private/json":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)

	c := regpypi.New(srv.Client(), "omni-audit-test")
	c.BaseURL = srv.URL

	st, err := c.Exists(context.Background(), "requests")
	if err != nil || st != registry.Exists {
		t.Fatalf("requests: status=%v err=%v", st, err)
	}
	st, err = c.Exists(context.Background(), "acme-private")
	if err != nil || st != registry.NotFound {
		t.Fatalf("acme-private: status=%v err=%v", st, err)
	}
}
