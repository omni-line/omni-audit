package registry

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Defaults for NewProber and NewHTTPClient.
const (
	DefaultTimeout   = 10 * time.Second
	DefaultRetries   = 2
	DefaultBaseDelay = 500 * time.Millisecond
	DefaultMaxDelay  = 10 * time.Second

	maxRedirects = 5
	// Bodies are drained up to this size so small responses keep the
	// connection reusable; larger bodies are abandoned instead of downloaded.
	maxDrainBytes = 64 << 10
	// Fetch reads at most this many bytes of a successful response body.
	maxFetchBytes = 1 << 20
)

// NewHTTPClient returns a client suited to registry probing: TLS 1.2+,
// proxy settings from the environment, a connection pool sized for
// concurrent checks against a handful of hosts, and redirect limits that
// refuse to downgrade from HTTPS.
func NewHTTPClient(timeout time.Duration, maxConnsPerHost int) *http.Client {
	if maxConnsPerHost <= 0 {
		maxConnsPerHost = 16
	}
	var t *http.Transport
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		t = dt.Clone()
	} else {
		t = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	t.MaxIdleConns = 4 * maxConnsPerHost
	t.MaxIdleConnsPerHost = maxConnsPerHost
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout:       timeout,
		Transport:     t,
		CheckRedirect: checkRedirect,
	}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect from https to %s", req.URL.Scheme)
	}
	host := req.URL.Hostname()
	if blockedRedirectHost(host) {
		return fmt.Errorf("refusing redirect to non-public host %q", host)
	}
	return nil
}

// blockedRedirectHosts are well-known cloud metadata / internal names that
// should never be followed even when the URL is not a literal IP.
var blockedRedirectHosts = map[string]struct{}{
	"metadata.google.internal":       {},
	"metadata.goog":                  {},
	"kubernetes.default":             {},
	"kubernetes.default.svc":         {},
	"kubernetes.default.svc.cluster": {},
}

func blockedRedirectHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return true
	}
	if _, bad := blockedRedirectHosts[host]; bad {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// Prober answers "does this URL exist?" with HEAD requests, falling back to
// GET when a server does not support HEAD, and retrying transient failures
// (network errors, 429, 5xx) with exponential backoff and Retry-After.
type Prober struct {
	Client    *http.Client
	UserAgent string
	// Retries is the number of additional attempts after a transient failure.
	Retries int
	// BaseDelay is the first backoff delay; it doubles on each retry.
	BaseDelay time.Duration
	// MaxDelay caps both computed backoff and server-provided Retry-After.
	MaxDelay time.Duration
}

// NewProber returns a Prober with default retry settings. A nil client gets
// NewHTTPClient(DefaultTimeout, 16).
func NewProber(client *http.Client, userAgent string) *Prober {
	if client == nil {
		client = NewHTTPClient(DefaultTimeout, 16)
	}
	return &Prober{
		Client:    client,
		UserAgent: userAgent,
		Retries:   DefaultRetries,
		BaseDelay: DefaultBaseDelay,
		MaxDelay:  DefaultMaxDelay,
	}
}

type attempt struct {
	status      Status
	err         error
	retry       bool
	retryAfter  time.Duration
	fallbackGET bool
}

// Probe maps an HTTP status to a Status: 2xx is Exists, 404/410 is NotFound,
// anything else is Unknown with a non-nil error.
func (p *Prober) Probe(ctx context.Context, rawURL string) (Status, error) {
	method := http.MethodHead
	var last attempt
	for i := 0; i <= p.Retries; i++ {
		if i > 0 {
			if err := sleep(ctx, p.delay(i, last.retryAfter)); err != nil {
				return Unknown, err
			}
		}
		last = p.once(ctx, method, rawURL)
		if last.fallbackGET && method == http.MethodHead {
			method = http.MethodGet
			last = p.once(ctx, method, rawURL)
		}
		if !last.retry {
			return last.status, last.err
		}
	}
	if p.Retries > 0 {
		return Unknown, fmt.Errorf("%w (gave up after %d attempts)", last.err, p.Retries+1)
	}
	return Unknown, last.err
}

// Fetch GETs rawURL and returns the response body. It retries transient
// failures (network errors, 429, 5xx) with the same backoff as Probe.
// 2xx yields the body and Exists; 404/410 yields nil and NotFound; any
// other status is Unknown with a non-nil error. Bodies larger than 1 MiB
// are truncated.
func (p *Prober) Fetch(ctx context.Context, rawURL string) ([]byte, Status, error) {
	var last fetchAttempt
	for i := 0; i <= p.Retries; i++ {
		if i > 0 {
			if err := sleep(ctx, p.delay(i, last.retryAfter)); err != nil {
				return nil, Unknown, err
			}
		}
		last = p.fetchOnce(ctx, rawURL)
		if !last.retry {
			return last.body, last.status, last.err
		}
	}
	if p.Retries > 0 {
		return nil, Unknown, fmt.Errorf("%w (gave up after %d attempts)", last.err, p.Retries+1)
	}
	return nil, Unknown, last.err
}

type fetchAttempt struct {
	body       []byte
	status     Status
	err        error
	retry      bool
	retryAfter time.Duration
}

func (p *Prober) fetchOnce(ctx context.Context, rawURL string) fetchAttempt {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fetchAttempt{status: Unknown, err: err}
	}
	if p.UserAgent != "" {
		req.Header.Set("User-Agent", p.UserAgent)
	}
	req.Header.Set("Accept", "application/json")

	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fetchAttempt{status: Unknown, err: ctxErr}
		}
		return fetchAttempt{status: Unknown, err: err, retry: true}
	}
	defer resp.Body.Close()

	code := resp.StatusCode
	switch {
	case code >= 200 && code < 300:
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes+1))
		if err != nil {
			return fetchAttempt{status: Unknown, err: err, retry: true}
		}
		if len(body) > maxFetchBytes {
			body = body[:maxFetchBytes]
		}
		return fetchAttempt{body: body, status: Exists}
	case code == http.StatusNotFound || code == http.StatusGone:
		_, _ = io.CopyN(io.Discard, resp.Body, maxDrainBytes)
		return fetchAttempt{status: NotFound}
	case code == http.StatusTooManyRequests || code >= 500:
		_, _ = io.CopyN(io.Discard, resp.Body, maxDrainBytes)
		return fetchAttempt{
			status:     Unknown,
			err:        statusError(req, code),
			retry:      true,
			retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
		}
	default:
		_, _ = io.CopyN(io.Discard, resp.Body, maxDrainBytes)
		return fetchAttempt{status: Unknown, err: statusError(req, code)}
	}
}

func (p *Prober) once(ctx context.Context, method, rawURL string) attempt {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return attempt{status: Unknown, err: err}
	}
	if p.UserAgent != "" {
		req.Header.Set("User-Agent", p.UserAgent)
	}
	req.Header.Set("Accept", "application/json")

	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return attempt{status: Unknown, err: ctxErr}
		}
		return attempt{status: Unknown, err: err, retry: true}
	}
	defer func() {
		_, _ = io.CopyN(io.Discard, resp.Body, maxDrainBytes)
		_ = resp.Body.Close()
	}()

	code := resp.StatusCode
	switch {
	case code >= 200 && code < 300:
		return attempt{status: Exists}
	case code == http.StatusNotFound || code == http.StatusGone:
		return attempt{status: NotFound}
	case (code == http.StatusMethodNotAllowed || code == http.StatusNotImplemented) && method == http.MethodHead:
		return attempt{status: Unknown, fallbackGET: true}
	case code == http.StatusTooManyRequests || code >= 500:
		return attempt{
			status:     Unknown,
			err:        statusError(req, code),
			retry:      true,
			retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
		}
	default:
		return attempt{status: Unknown, err: statusError(req, code)}
	}
}

func statusError(req *http.Request, code int) error {
	return fmt.Errorf("%s %s: unexpected HTTP %d", req.Method, req.URL.Redacted(), code)
}

func (p *Prober) delay(retry int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		if p.MaxDelay > 0 && retryAfter > p.MaxDelay {
			return p.MaxDelay
		}
		return retryAfter
	}
	d := p.BaseDelay << (retry - 1)
	if d <= 0 || (p.MaxDelay > 0 && d > p.MaxDelay) {
		d = p.MaxDelay
	}
	if d <= 0 {
		return 0
	}
	// Jitter in [d/2, d) spreads retries from concurrent workers.
	half := int64(d / 2)
	return time.Duration(half + rand.Int63n(half+1)) //nolint:gosec // jitter, not security sensitive
}

func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
