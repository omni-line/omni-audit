package rubygems_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/omni-line/omni-audit/internal/registry"
	regruby "github.com/omni-line/omni-audit/internal/registry/rubygems"
)

func TestExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/gems/rails.json", "/api/v1/gems/nokogiri.json":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/gems/acme-private.json":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(srv.Close)

	c := regruby.New(registry.NewProber(srv.Client(), "omni-audit-test"))
	c.BaseURL = srv.URL

	cases := map[string]registry.Status{
		"rails":        registry.Exists,
		"Nokogiri":     registry.Exists,
		"acme-private": registry.NotFound,
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

	c := regruby.New(registry.NewProber(srv.Client(), "test"))
	c.BaseURL = srv.URL

	for _, name := range []string{"", "..", ".hidden", "-dash", "_under", "123", "has space", "a/b", "gem!"} {
		st, err := c.Exists(context.Background(), name)
		if st != registry.Unknown || !errors.Is(err, registry.ErrInvalidName) {
			t.Errorf("%q: status=%v err=%v", name, st, err)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid names made %d requests", calls)
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"Rails":      "rails",
		"NOKOGIRI":   "nokogiri",
		"  Foo-Bar ": "foo-bar",
	}
	for in, want := range cases {
		if got := regruby.Normalize(in); got != want {
			t.Errorf("Normalize(%q)=%q want %q", in, got, want)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, name := range []string{"rails", "nokogiri", "a", "1a", "foo_bar", "foo-bar", "foo.bar"} {
		if !regruby.ValidName(name) {
			t.Errorf("%q should be valid", name)
		}
	}
	for _, name := range []string{"", ".rails", "-rails", "_rails", "123", "has space"} {
		if regruby.ValidName(name) {
			t.Errorf("%q should be invalid", name)
		}
	}
}

func TestPackageURL(t *testing.T) {
	got := regruby.PackageURL("Rails")
	want := "https://rubygems.org/gems/rails"
	if got != want {
		t.Fatalf("PackageURL = %q want %q", got, want)
	}
}
