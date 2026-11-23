package traefik

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/maxfield-allison/dnsweaver/pkg/httputil"
)

// DefaultAPIExcludeProviders lists the Traefik providers whose routers are
// ignored by API discovery unless overridden. Routers from the "internal"
// provider (api@internal, dashboard@internal, the HTTP→HTTPS redirect, ...)
// never carry user hostnames.
var DefaultAPIExcludeProviders = []string{"internal"}

// DefaultAPITimeout bounds a single request to the Traefik API.
const DefaultAPITimeout = 10 * time.Second

// apiPageSize is the page size requested from the Traefik API. Traefik caps
// per_page server-side; 100 keeps the number of round trips low without
// relying on a larger cap.
const apiPageSize = 100

// apiMaxPages guards against a misbehaving server that keeps advertising a
// next page. 1000 pages of 100 routers is far beyond any real deployment.
const apiMaxPages = 1000

// apiStatusEnabled is the router status Traefik reports for routers that are
// actually serving traffic. Routers in "disabled" or "warning" state are
// skipped so DNS is not published for hostnames Traefik will not route.
const apiStatusEnabled = "enabled"

// APIDiscoveryConfig configures discovery of routers from Traefik's REST API
// (GET /api/http/routers). Unlike label parsing, the API returns the routers
// Traefik actually built, including those generated from a provider's
// `defaultRule` for containers that carry no Host() label, and routers from
// every provider (docker, file, kubernetes, ...).
//
// Design principle: presence implies intent. Setting URL enables API
// discovery; no separate enabled flag is needed.
type APIDiscoveryConfig struct {
	// URL is the base URL of the Traefik API, e.g. "http://127.0.0.1:8080"
	// or "https://traefik.example.com". The "/api/http/routers" path is
	// appended, so a base path prefix is preserved.
	URL string

	// Username and Password enable HTTP basic authentication, for APIs
	// exposed through a router protected by the basicAuth middleware.
	Username string
	Password string

	// ExcludeProviders lists Traefik provider names (the part after "@" in a
	// router name) whose routers are ignored. nil means
	// DefaultAPIExcludeProviders; an empty non-nil slice excludes nothing.
	ExcludeProviders []string

	// TLSSkipVerify disables certificate verification for HTTPS API URLs.
	TLSSkipVerify bool

	// Timeout bounds each request. Zero means DefaultAPITimeout.
	Timeout time.Duration

	// HTTPClient overrides the client used for requests (tests only).
	HTTPClient *http.Client
}

// IsEnabled reports whether API discovery is configured.
func (c APIDiscoveryConfig) IsEnabled() bool {
	return c.URL != ""
}

// apiRouter is the subset of Traefik's router representation used for
// hostname discovery.
type apiRouter struct {
	Name        string   `json:"name"`
	Rule        string   `json:"rule"`
	Provider    string   `json:"provider"`
	Status      string   `json:"status"`
	EntryPoints []string `json:"entryPoints"`
	// Using lists the entrypoints the router is effectively bound to, after
	// Traefik resolved `asDefault` entrypoints. Preferred over EntryPoints.
	Using []string `json:"using"`
}

// apiClient fetches routers from the Traefik API.
type apiClient struct {
	routersURL *url.URL
	username   string
	password   string
	exclude    map[string]struct{}
	http       *http.Client
}

func newAPIClient(cfg APIDiscoveryConfig, httpClient *http.Client) (*apiClient, error) {
	base, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil {
		return nil, fmt.Errorf("parsing traefik api url: %w", err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("traefik api url must use http or https, got %q", base.Scheme)
	}
	if base.Host == "" {
		return nil, fmt.Errorf("traefik api url %q has no host", cfg.URL)
	}

	exclude := cfg.ExcludeProviders
	if exclude == nil {
		exclude = DefaultAPIExcludeProviders
	}
	excludeSet := make(map[string]struct{}, len(exclude))
	for _, p := range exclude {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			excludeSet[p] = struct{}{}
		}
	}

	return &apiClient{
		routersURL: base.JoinPath("api", "http", "routers"),
		username:   cfg.Username,
		password:   cfg.Password,
		exclude:    excludeSet,
		http:       httpClient,
	}, nil
}

// endpoint returns the routers URL without credentials, for logging.
func (c *apiClient) endpoint() string {
	u := *c.routersURL
	u.User = nil
	return u.String()
}

// fetchRouters returns every HTTP router, following Traefik's X-Next-Page
// pagination. Any transport, status or decoding error aborts discovery so the
// caller reports an incomplete snapshot instead of a partial one.
func (c *apiClient) fetchRouters(ctx context.Context) ([]apiRouter, error) {
	var all []apiRouter
	for page := 1; page <= apiMaxPages; {
		routers, next, err := c.fetchPage(ctx, page)
		if err != nil {
			return nil, err
		}
		all = append(all, routers...)
		if next <= page {
			return all, nil
		}
		page = next
	}
	return nil, fmt.Errorf("traefik api pagination exceeded %d pages", apiMaxPages)
}

func (c *apiClient) fetchPage(ctx context.Context, page int) ([]apiRouter, int, error) {
	u := *c.routersURL
	q := u.Query()
	q.Set("per_page", strconv.Itoa(apiPageSize))
	q.Set("page", strconv.Itoa(page))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("building traefik api request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, httputil.RedactRequestError(fmt.Errorf("querying traefik api: %w", err), c.password)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("traefik api %s returned HTTP %d", c.endpoint(), resp.StatusCode)
	}

	body, err := httputil.ReadBody(resp, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("reading traefik api response: %w", err)
	}

	var routers []apiRouter
	if err := json.Unmarshal(body, &routers); err != nil {
		return nil, 0, fmt.Errorf("decoding traefik api response: %w", err)
	}

	next := 0
	if h := resp.Header.Get("X-Next-Page"); h != "" {
		if n, convErr := strconv.Atoi(h); convErr == nil {
			next = n
		}
	}
	return routers, next, nil
}

// include reports whether a router should contribute hostnames.
func (c *apiClient) include(r apiRouter) bool {
	if r.Status != "" && r.Status != apiStatusEnabled {
		return false
	}
	_, excluded := c.exclude[strings.ToLower(routerProvider(r))]
	return !excluded
}

// routerProvider returns the router's provider, falling back to the
// "@provider" suffix of its name for API versions that omit the field.
func routerProvider(r apiRouter) string {
	if r.Provider != "" {
		return r.Provider
	}
	if i := strings.LastIndex(r.Name, "@"); i >= 0 {
		return r.Name[i+1:]
	}
	return ""
}

// DiscoverFromAPI fetches routers from the Traefik API and extracts hostnames
// using the same entrypoint semantics as file discovery.
func (p *Parser) DiscoverFromAPI(ctx context.Context, c *apiClient) ([]HostnameExtraction, error) {
	routers, err := c.fetchRouters(ctx)
	if err != nil {
		return nil, err
	}

	type seenKey struct {
		hostname   string
		entrypoint string
	}
	seen := make(map[seenKey]struct{})
	var extractions []HostnameExtraction
	skipped := 0

	for _, r := range routers {
		if !c.include(r) {
			skipped++
			continue
		}
		eps := r.Using
		if len(eps) == 0 {
			eps = r.EntryPoints
		}
		for _, e := range p.extractRouter(r.Name, r.Rule, eps, "api", c.endpoint()) {
			k := seenKey{hostname: e.Hostname, entrypoint: e.EntryPoint}
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			extractions = append(extractions, e)
		}
	}

	p.logger.Debug("fetched traefik routers from api",
		"endpoint", c.endpoint(),
		"routers", len(routers),
		"skipped", skipped,
		"extractions", len(extractions),
	)
	return extractions, nil
}
