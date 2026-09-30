package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testProber() *Prober {
	return &Prober{
		Client:    NewHTTPClient(2*time.Second, 4),
		UserAgent: "omni-audit-test",
		Retries:   2,
		BaseDelay: time.Millisecond,
		MaxDelay:  5 * time.Millisecond,
	}
}

func TestProbeStatusMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("method=%s want HEAD", r.Method)
		}
		if got := r.Header.Get("User-Agent"); got != "omni-audit-test" {
			t.Errorf("user-agent=%q", got)
		}
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
		case "/gone":
			w.WriteHeader(http.StatusGone)
		case "/teapot":
			w.WriteHeader(http.StatusTeapot)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	p := testProber()

	cases := []struct {
		path    string
		want    Status
		wantErr bool
	}{
		{"/ok", Exists, false},
		{"/missing", NotFound, false},
		{"/gone", NotFound, false},
		{"/teapot", Unknown, true},
	}
	for _, tc := range cases {
		st, err := p.Probe(context.Background(), srv.URL+tc.path)
		if st != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("%s: status=%v err=%v, want %v (err=%v)", tc.path, st, err, tc.want, tc.wantErr)
		}
	}
}

func TestProbeFallsBackToGETWhenHEADUnsupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	st, err := testProber().Probe(context.Background(), srv.URL+"/x")
	if err != nil || st != Exists {
		t.Fatalf("status=%v err=%v", st, err)
	}
}

func TestProbeRetriesTransientFailures(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch atomic.AddInt32(&calls, 1) {
		case 1:
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	st, err := testProber().Probe(context.Background(), srv.URL+"/x")
	if err != nil || st != NotFound {
		t.Fatalf("status=%v err=%v", st, err)
	}
	if calls != 3 {
		t.Fatalf("calls=%d want 3", calls)
	}
}

func TestProbeGivesUpAfterRetries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)

	st, err := testProber().Probe(context.Background(), srv.URL+"/x")
	if st != Unknown || err == nil {
		t.Fatalf("status=%v err=%v", st, err)
	}
	if !strings.Contains(err.Error(), "3 attempts") {
		t.Fatalf("error should mention attempts: %v", err)
	}
	if calls != 3 {
		t.Fatalf("calls=%d want 3", calls)
	}
}

func TestProbeDoesNotRetryClientErrors(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	if _, err := testProber().Probe(context.Background(), srv.URL+"/x"); err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("calls=%d want 1", calls)
	}
}

func TestProbeHonorsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	p := testProber()
	p.BaseDelay = time.Hour
	p.MaxDelay = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := p.Probe(ctx, srv.URL+"/x")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v want deadline exceeded", err)
	}
}

func TestRedirectDowngradeRefused(t *testing.T) {
	via := []*http.Request{{URL: mustURL(t, "https://registry.example/x")}}
	next := &http.Request{URL: mustURL(t, "http://evil.example/x")}
	if err := checkRedirect(next, via); err == nil {
		t.Fatal("expected https->http redirect to be refused")
	}
	next.URL = mustURL(t, "https://registry.example/y")
	if err := checkRedirect(next, via); err != nil {
		t.Fatalf("https->https redirect refused: %v", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := parseRetryAfter("3", now); got != 3*time.Second {
		t.Fatalf("seconds: %v", got)
	}
	if got := parseRetryAfter(now.Add(2*time.Second).Format(http.TimeFormat), now); got != 2*time.Second {
		t.Fatalf("http-date: %v", got)
	}
	if got := parseRetryAfter("garbage", now); got != 0 {
		t.Fatalf("garbage: %v", got)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
