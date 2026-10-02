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
		case "/pypi/requests/json", "/pypi/flask-login/json":
			w.WriteHeader(http.StatusOK)
		case "/pypi/acme-private/json":
			w.WriteHeader(http.StatusNotFound)
		case "/simple/acme-private/":
			w.WriteHeader(http.StatusNotFound)
		case "/pypi/test/json":
			// Registered project with no releases: JSON 404, Simple 200.
			w.WriteHeader(http.StatusNotFound)
		case "/simple/test/":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)

	c := regpypi.New(registry.NewProber(srv.Client(), "omni-audit-test"))
	c.BaseURL = srv.URL

	cases := map[string]registry.Status{
		"requests":     registry.Exists,
		"Flask_Login":  registry.Exists,
		"acme.private": registry.NotFound,
		"test":         registry.Exists,
	}
	for name, want := range cases {
		st, err := c.Exists(context.Background(), name)
		if err != nil || st != want {
			t.Errorf("%s: status=%v err=%v want %v", name, st, err, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"Flask_Login":    "flask-login",
		"zope.interface": "zope-interface",
		"A__B--C..D":     "a-b-c-d",
		"requests":       "requests",
		"Typing.Extras":  "typing-extras",
	}
	for in, want := range cases {
		if got := regpypi.Normalize(in); got != want {
			t.Errorf("Normalize(%q)=%q want %q", in, got, want)
		}
	}
}
