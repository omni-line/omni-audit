package goproxy_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/omni-line/omni-audit/internal/registry"
	"github.com/omni-line/omni-audit/internal/registry/goproxy"
)

func TestEscapePath(t *testing.T) {
	got, ok := goproxy.EscapePath("example.com/Internal/SDK")
	if !ok || got != "example.com/!internal/!s!d!k" {
		// Internal → !internal, SDK → !s!d!k
		t.Fatalf("got %q ok=%v", got, ok)
	}
	got, _ = goproxy.EscapePath("github.com/foo/bar")
	if got != "github.com/foo/bar" {
		t.Fatalf("got %q", got)
	}
}

func TestValidName(t *testing.T) {
	cases := map[string]bool{
		"github.com/foo/bar":   true,
		"example.com/Internal": true,
		"rsc.io":               true,
		"mycompany/foo":        false,
		"../rel":               false,
		"":                     false,
		"/abs/path":            false,
	}
	for name, want := range cases {
		if got := goproxy.ValidName(name); got != want {
			t.Errorf("ValidName(%q)=%v want %v", name, got, want)
		}
	}
}

func TestExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/github.com/google/uuid/@v/list":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("v1.6.0\n"))
		case "/example.com/!private/@v/list":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)

	c := goproxy.New(registry.NewProber(srv.Client(), "test"))
	c.BaseURL = srv.URL

	st, err := c.Exists(context.Background(), "github.com/google/uuid")
	if err != nil || st != registry.Exists {
		t.Fatalf("uuid: status=%v err=%v", st, err)
	}
	st, err = c.Exists(context.Background(), "example.com/Private")
	if err != nil || st != registry.NotFound {
		t.Fatalf("Private: status=%v err=%v", st, err)
	}
	_, err = c.Exists(context.Background(), "mycompany/foo")
	if err == nil {
		t.Fatal("expected invalid name error")
	}
}
