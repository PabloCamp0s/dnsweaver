package traefik

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
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

// DefaultAPIDropGrace is how long a suspicious drop in the router list (a
// provider vanishing, or the list shrinking by more than half) is held back
// before it is accepted as real. See APIDiscoveryConfig.DropGrace.
const DefaultAPIDropGrace = 5 * time.Minute

// DefaultAPIStartupSettle is how long Traefik must have been running before
// its router list is trusted as complete. See APIDiscoveryConfig.StartupSettle.
const DefaultAPIStartupSettle = 60 * time.Second

// apiPageSize is the page size requested from the Traefik API. Traefik does
// not cap per_page, so a large page returns the whole router list in a single
// response for practically every deployment. A single response cannot be torn
// by routers changing between pages.
const apiPageSize = 1000

// apiConsistentReads bounds how many extra full reads are attempted when the
// router list spans several pages and changes between reads.
const apiConsistentReads = 3

// apiDropMinRouters is the minimum size of the previously accepted router
// list for a "shrank by more than half" drop to count as suspicious. Small
// lists legitimately halve when one or two containers stop.
const apiDropMinRouters = 5

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

	// DropGrace guards against snapshots that Traefik reports successfully but
	// that are incomplete, e.g. while a provider is still starting after a
	// Traefik restart. When a provider that previously had routers vanishes,
	// or the router list shrinks by more than half, the previous routers are
	// kept (merged with the new ones) until the drop has persisted for
	// DropGrace; only then are their hostnames allowed to be removed. New
	// routers are still published immediately. Zero means DefaultAPIDropGrace;
	// a negative value disables the guard.
	DropGrace time.Duration

	// StartupSettle guards against Traefik restarts. Traefik reports its start
	// time in /api/version; until it has been running for StartupSettle, its
	// providers may still be loading routers. If dnsweaver has no accepted
	// router list yet (it started at the same time as Traefik), discovery
	// fails for the cycle so nothing is created or removed. If Traefik
	// restarted while dnsweaver was running, the previous routers are kept
	// merged with the new ones until it settles. When /api/version cannot be
	// read, this guard is skipped. Zero means DefaultAPIStartupSettle; a
	// negative value disables the guard.
	StartupSettle time.Duration

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
	logger     *slog.Logger
	dropGrace  time.Duration
	settle     time.Duration
	versionURL *url.URL
	now        func() time.Time

	// Drop guard state: the last router list accepted as complete, and when
	// the current suspicious drop was first seen (zero if none).
	mu            sync.Mutex
	accepted      []apiRouter
	acceptedStart time.Time // Traefik start time when accepted was taken (zero if unknown)
	holdSince     time.Time

	// Startup guard logging state, so repeated polls do not repeat warnings.
	versionUnavailableLogged bool
	restartLoggedFor         time.Time
}

func newAPIClient(cfg APIDiscoveryConfig, httpClient *http.Client, logger *slog.Logger) (*apiClient, error) {
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

	dropGrace := cfg.DropGrace
	if dropGrace == 0 {
		dropGrace = DefaultAPIDropGrace
	}
	settle := cfg.StartupSettle
	if settle == 0 {
		settle = DefaultAPIStartupSettle
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &apiClient{
		routersURL: base.JoinPath("api", "http", "routers"),
		versionURL: base.JoinPath("api", "version"),
		username:   cfg.Username,
		password:   cfg.Password,
		exclude:    excludeSet,
		http:       httpClient,
		logger:     logger,
		dropGrace:  dropGrace,
		settle:     settle,
		now:        time.Now,
	}, nil
}

// endpoint returns the routers URL without credentials, for logging.
func (c *apiClient) endpoint() string {
	u := *c.routersURL
	u.User = nil
	return u.String()
}

// fetchRouters returns every HTTP router. Any transport, status or decoding
// error aborts discovery so the caller reports an incomplete snapshot instead
// of a partial one.
//
// The list is normally returned in one page. If it spans several pages, a
// router added or removed between page requests can shift the page boundaries
// and make a successful read miss an active router, so the full list is read
// again until two consecutive reads agree.
func (c *apiClient) fetchRouters(ctx context.Context) ([]apiRouter, error) {
	routers, pages, err := c.fetchAllPages(ctx)
	if err != nil {
		return nil, err
	}
	if pages == 1 {
		return routers, nil
	}
	for attempt := 0; attempt < apiConsistentReads; attempt++ {
		again, _, err := c.fetchAllPages(ctx)
		if err != nil {
			return nil, err
		}
		if routerListsEqual(routers, again) {
			return again, nil
		}
		routers = again
	}
	return nil, fmt.Errorf("traefik api router list changed between paginated reads %d times in a row", apiConsistentReads)
}

// fetchAllPages reads every page once, following Traefik's X-Next-Page header.
func (c *apiClient) fetchAllPages(ctx context.Context) ([]apiRouter, int, error) {
	var all []apiRouter
	pages := 0
	for page := 1; page <= apiMaxPages; {
		routers, next, err := c.fetchPage(ctx, page)
		if err != nil {
			return nil, 0, err
		}
		pages++
		all = append(all, routers...)
		if next <= page {
			return all, pages, nil
		}
		page = next
	}
	return nil, 0, fmt.Errorf("traefik api pagination exceeded %d pages", apiMaxPages)
}

// routerListsEqual reports whether two reads returned the same routers with
// the same hostname-relevant fields, ignoring order.
func routerListsEqual(a, b []apiRouter) bool {
	if len(a) != len(b) {
		return false
	}
	ka, kb := routerKeys(a), routerKeys(b)
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
	}
	return true
}

func routerKeys(rs []apiRouter) []string {
	keys := make([]string, 0, len(rs))
	for _, r := range rs {
		keys = append(keys, strings.Join([]string{
			r.Name, r.Provider, r.Status, r.Rule,
			strings.Join(r.Using, ","), strings.Join(r.EntryPoints, ","),
		}, "\x00"))
	}
	sort.Strings(keys)
	return keys
}

// traefikStart returns when Traefik started, from GET /api/version. known is
// false when the startup guard is disabled or the endpoint cannot be read (for
// example an API restricted to /api/http/routers), in which case discovery
// proceeds without the guard.
func (c *apiClient) traefikStart(ctx context.Context) (start time.Time, known bool) {
	if c.settle < 0 {
		return time.Time{}, false
	}
	start, err := c.fetchStartDate(ctx)
	if err != nil || start.IsZero() {
		c.mu.Lock()
		if !c.versionUnavailableLogged {
			c.versionUnavailableLogged = true
			c.logger.Info("traefik start time unavailable; startup guard disabled",
				"endpoint", c.endpoint(), "error", fmt.Sprint(err))
		}
		c.mu.Unlock()
		return time.Time{}, false
	}
	return start, true
}

func (c *apiClient) fetchStartDate(ctx context.Context) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.versionURL.String(), nil)
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Accept", "application/json")
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return time.Time{}, httputil.RedactRequestError(err, c.password)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := httputil.ReadBody(resp, 64*1024)
	if err != nil {
		return time.Time{}, err
	}
	var v struct {
		StartDate time.Time `json:"startDate"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return time.Time{}, err
	}
	return v.StartDate, nil
}

// stabilize applies the startup and drop guards to the routers that passed
// filtering, and returns the routers whose hostnames should be published.
//
// Traefik can answer successfully with an incomplete router list, for example
// right after a restart while its Docker provider is not yet available:
//
//   - Startup guard: while Traefik has been running for less than settle, its
//     list is not trusted. Without a previously accepted list (dnsweaver
//     started together with Traefik) an error is returned so the cycle is
//     treated as incomplete; with one (Traefik restarted under a running
//     dnsweaver), the previous routers are merged back in.
//   - Drop guard: if the list looks incomplete (a provider that had routers is
//     gone, or the list shrank by more than half), the previous routers are
//     merged back in until the drop has persisted for dropGrace.
//
// While merging, new routers are still published; only removals are held.
func (c *apiClient) stabilize(current []apiRouter, start time.Time, startKnown bool) ([]apiRouter, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	settling := startKnown && c.settle > 0 && now.Sub(start) < c.settle

	if c.accepted == nil {
		if settling {
			return nil, fmt.Errorf("traefik started %s ago; waiting until it has run for %s before trusting its router list",
				now.Sub(start).Round(time.Second), c.settle)
		}
		c.accept(current, start, startKnown)
		return current, nil
	}

	if settling && !c.acceptedStart.IsZero() && !start.Equal(c.acceptedStart) {
		if !c.restartLoggedFor.Equal(start) {
			c.restartLoggedFor = start
			c.logger.Warn("traefik restarted; keeping previous hostnames until it settles",
				"endpoint", c.endpoint(),
				"started", start.UTC().Format(time.RFC3339),
				"settle", c.settle.String(),
			)
		}
		return mergeRouters(c.accepted, current), nil
	}

	if c.dropGrace < 0 {
		c.accept(current, start, startKnown)
		return current, nil
	}

	reason := suspiciousDrop(c.accepted, current)
	if reason == "" {
		if !c.holdSince.IsZero() {
			c.logger.Info("traefik api router list recovered; drop guard released",
				"endpoint", c.endpoint())
		}
		c.accept(current, start, startKnown)
		return current, nil
	}

	if c.holdSince.IsZero() {
		c.holdSince = now
		c.logger.Warn("traefik api router list dropped suspiciously; keeping previous hostnames",
			"endpoint", c.endpoint(),
			"reason", reason,
			"grace", c.dropGrace.String(),
		)
	}
	if held := now.Sub(c.holdSince); held >= c.dropGrace {
		c.logger.Warn("traefik api router drop persisted past grace period; accepting it",
			"endpoint", c.endpoint(),
			"reason", reason,
			"held", held.Round(time.Second).String(),
		)
		c.accept(current, start, startKnown)
		return current, nil
	}
	return mergeRouters(c.accepted, current), nil
}

// accept records current as the last complete router list. Callers hold c.mu.
func (c *apiClient) accept(current []apiRouter, start time.Time, startKnown bool) {
	c.accepted = append([]apiRouter{}, current...)
	c.holdSince = time.Time{}
	if startKnown {
		c.acceptedStart = start
	}
}

// suspiciousDrop explains why current looks like an incomplete version of
// previous, or returns "" if it does not.
func suspiciousDrop(previous, current []apiRouter) string {
	prevByProvider := countByProvider(previous)
	curByProvider := countByProvider(current)
	var vanished []string
	for provider, n := range prevByProvider {
		if n > 0 && curByProvider[provider] == 0 {
			vanished = append(vanished, provider)
		}
	}
	if len(vanished) > 0 {
		sort.Strings(vanished)
		return fmt.Sprintf("provider %s no longer reports any router", strings.Join(vanished, ", "))
	}
	if len(previous) >= apiDropMinRouters && len(current)*2 < len(previous) {
		return fmt.Sprintf("router count dropped from %d to %d", len(previous), len(current))
	}
	return ""
}

func countByProvider(rs []apiRouter) map[string]int {
	counts := make(map[string]int)
	for _, r := range rs {
		counts[strings.ToLower(routerProvider(r))]++
	}
	return counts
}

// mergeRouters returns current plus every previous router whose name is not
// in current, so held-back hostnames stay published during the grace period.
func mergeRouters(previous, current []apiRouter) []apiRouter {
	seen := make(map[string]struct{}, len(current))
	merged := append([]apiRouter{}, current...)
	for _, r := range current {
		seen[r.Name] = struct{}{}
	}
	for _, r := range previous {
		if _, ok := seen[r.Name]; !ok {
			merged = append(merged, r)
		}
	}
	return merged
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
	start, startKnown := c.traefikStart(ctx)
	fetched, err := c.fetchRouters(ctx)
	if err != nil {
		return nil, err
	}

	var included []apiRouter
	skipped := 0
	for _, r := range fetched {
		if !c.include(r) {
			skipped++
			continue
		}
		included = append(included, r)
	}
	routers, err := c.stabilize(included, start, startKnown)
	if err != nil {
		return nil, err
	}

	type seenKey struct {
		hostname   string
		entrypoint string
	}
	seen := make(map[seenKey]struct{})
	var extractions []HostnameExtraction

	for _, r := range routers {
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
		"routers", len(fetched),
		"skipped", skipped,
		"published", len(routers),
		"extractions", len(extractions),
	)
	return extractions, nil
}
