package npm_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/omni-line/omni-audit/internal/registry"
	regnpm "github.com/omni-line/omni-audit/internal/registry/npm"
)

func TestExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lodash":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case "/@acme/missing", "/@acme%2Fmissing", "/missing-pkg":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)

	c := regnpm.New(srv.Client(), "omni-audit-test")
	c.BaseURL = srv.URL

	st, err := c.Exists(context.Background(), "lodash")
	if err != nil || st != registry.Exists {
		t.Fatalf("lodash: status=%v err=%v", st, err)
	}

	st, err = c.Exists(context.Background(), "@acme/missing")
	if err != nil || st != registry.NotFound {
		t.Fatalf("@acme/missing: status=%v err=%v", st, err)
	}

	st, err = c.Exists(context.Background(), "missing-pkg")
	if err != nil || st != registry.NotFound {
		t.Fatalf("missing-pkg: status=%v err=%v", st, err)
	}
}
