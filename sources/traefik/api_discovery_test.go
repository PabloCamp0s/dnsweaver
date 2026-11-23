package traefik

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/maxfield-allison/dnsweaver/pkg/source"
)

// fakeTraefikAPI serves /api/http/routers like Traefik does, paginating the
// given routers with the requested per_page and an X-Next-Page header (Traefik
// sends X-Next-Page: 1 on the last page).
type fakeTraefikAPI struct {
	routers  []apiRouter
	username string
	password string
	status   atomic.Int32 // when non-zero, every request returns this status
	body     string       // when non-empty, returned verbatim instead of JSON routers
	requests atomic.Int32
	lastPath atomic.Value
}

func (f *fakeTraefikAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	f.lastPath.Store(r.URL.Path)

	if f.username != "" || f.password != "" {
		u, p, ok := r.BasicAuth()
		if !ok || u != f.username || p != f.password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	if s := f.status.Load(); s != 0 {
		w.WriteHeader(int(s))
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/api/http/routers") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if f.body != "" {
		_, _ = w.Write([]byte(f.body))
		return
	}

	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage <= 0 {
		perPage = 100
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * perPage
	end := start + perPage
	if start > len(f.routers) {
		start = len(f.routers)
	}
	if end > len(f.routers) {
		end = len(f.routers)
	}
	next := 1
	if end < len(f.routers) {
		next = page + 1
	}
	w.Header().Set("X-Next-Page", strconv.Itoa(next))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(f.routers[start:end])
}

func failingAPI(status int) *fakeTraefikAPI {
	f := &fakeTraefikAPI{}
	f.status.Store(int32(status))
	return f
}

func newAPISource(t *testing.T, api *fakeTraefikAPI, cfg APIDiscoveryConfig, opts ...Option) *Traefik {
	t.Helper()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	if cfg.URL == "" {
		cfg.URL = srv.URL
	} else {
		cfg.URL = srv.URL + cfg.URL // relative suffix (e.g. a base path)
	}
	opts = append([]Option{WithLogger(testLogger()), WithAPIDiscovery(cfg)}, opts...)
	return New(opts...)
}

// hostEntrypoints flattens hostnames into sorted "host|entrypoint" strings.
func hostEntrypoints(hs []source.Hostname) []string {
	out := make([]string, 0, len(hs))
	for _, h := range hs {
		out = append(out, h.Name+"|"+h.Metadata[MetadataKeyEntryPoint])
	}
	sort.Strings(out)
	return out
}

func assertStrings(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d entries %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d = %q, want %q (got %v)", i, got[i], want[i], got)
		}
	}
}

func TestAPIDiscovery_SupportsDiscoveryWithAPIOnly(t *testing.T) {
	src := New(WithLogger(testLogger()), WithAPIDiscovery(APIDiscoveryConfig{URL: "http://127.0.0.1:8080"}))
	if !src.SupportsDiscovery() {
		t.Fatal("SupportsDiscovery() = false with an API URL configured")
	}
	if !src.SupportsAPIDiscovery() {
		t.Fatal("SupportsAPIDiscovery() = false with an API URL configured")
	}
	if New().SupportsAPIDiscovery() {
		t.Fatal("SupportsAPIDiscovery() = true without configuration")
	}
}

func TestAPIDiscovery_DefaultRuleRouters(t *testing.T) {
	api := &fakeTraefikAPI{routers: []apiRouter{
		{
			// Router generated from a provider defaultRule: whitespace and a
			// HostRegexp alternative that must be ignored.
			Name:     "web-secure-whoami@docker",
			Provider: "docker",
			Status:   "enabled",
			Rule:     "Host( `whoami.example.com` ) || Host( `whoami.node.example.com` ) || HostRegexp( `^whoami\\.example\\.lan$` )",
			Using:    []string{"web-secure"},
		},
	}}
	src := newAPISource(t, api, APIDiscoveryConfig{})

	hs, err := src.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	assertStrings(t, hostEntrypoints(hs), []string{
		"whoami.example.com|web-secure",
		"whoami.node.example.com|web-secure",
	})
	for _, h := range hs {
		if h.Source != "traefik" || h.Router != "web-secure-whoami@docker" {
			t.Fatalf("unexpected attribution: %+v", h)
		}
	}
}

func TestAPIDiscovery_Filtering(t *testing.T) {
	routers := []apiRouter{
		{Name: "app@docker", Provider: "docker", Status: "enabled", Rule: "Host(`app.example.com`)"},
		{Name: "disabled@docker", Provider: "docker", Status: "disabled", Rule: "Host(`disabled.example.com`)"},
		{Name: "warning@docker", Provider: "docker", Status: "warning", Rule: "Host(`warning.example.com`)"},
		{Name: "dashboard@internal", Provider: "internal", Status: "enabled", Rule: "Host(`dash.example.com`)"},
		{Name: "static@file", Provider: "file", Status: "enabled", Rule: "Host(`static.example.com`)"},
		// No provider field: provider is taken from the @suffix of the name.
		{Name: "legacy@file", Status: "enabled", Rule: "Host(`legacy.example.com`)"},
		{Name: "catchall@docker", Provider: "docker", Status: "enabled", Rule: "PathPrefix(`/`)"},
	}

	tests := []struct {
		name    string
		exclude []string
		want    []string
	}{
		{
			name:    "default excludes internal",
			exclude: nil,
			want:    []string{"app.example.com|", "legacy.example.com|", "static.example.com|"},
		},
		{
			name:    "custom exclusion replaces default",
			exclude: []string{"file"},
			want:    []string{"app.example.com|", "dash.example.com|"},
		},
		{
			name:    "empty exclusion includes every provider",
			exclude: []string{},
			want:    []string{"app.example.com|", "dash.example.com|", "legacy.example.com|", "static.example.com|"},
		},
		{
			name:    "provider names are case-insensitive",
			exclude: []string{"INTERNAL", " File "},
			want:    []string{"app.example.com|"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := newAPISource(t, &fakeTraefikAPI{routers: routers}, APIDiscoveryConfig{ExcludeProviders: tt.exclude})
			hs, err := src.Discover(context.Background())
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}
			assertStrings(t, hostEntrypoints(hs), tt.want)
		})
	}
}

func TestAPIDiscovery_EntryPoints(t *testing.T) {
	routers := []apiRouter{
		// using (effective entrypoints) wins over entryPoints.
		{Name: "a@docker", Provider: "docker", Status: "enabled", Rule: "Host(`a.example.com`)",
			EntryPoints: []string{"declared"}, Using: []string{"web", "websecure"}},
		// entryPoints used when using is absent.
		{Name: "b@docker", Provider: "docker", Status: "enabled", Rule: "Host(`b.example.com`)",
			EntryPoints: []string{"websecure"}},
		// neither: default entrypoints, else wildcard.
		{Name: "c@docker", Provider: "docker", Status: "enabled", Rule: "Host(`c.example.com`)"},
	}

	t.Run("without default entrypoints", func(t *testing.T) {
		src := newAPISource(t, &fakeTraefikAPI{routers: routers}, APIDiscoveryConfig{})
		hs, err := src.Discover(context.Background())
		if err != nil {
			t.Fatalf("Discover: %v", err)
		}
		assertStrings(t, hostEntrypoints(hs), []string{
			"a.example.com|web", "a.example.com|websecure", "b.example.com|websecure", "c.example.com|",
		})
	})

	t.Run("with default entrypoints", func(t *testing.T) {
		src := newAPISource(t, &fakeTraefikAPI{routers: routers}, APIDiscoveryConfig{},
			WithDefaultEntryPoints([]string{"internal-ep"}))
		hs, err := src.Discover(context.Background())
		if err != nil {
			t.Fatalf("Discover: %v", err)
		}
		assertStrings(t, hostEntrypoints(hs), []string{
			"a.example.com|web", "a.example.com|websecure", "b.example.com|websecure", "c.example.com|internal-ep",
		})
	})
}

func TestAPIDiscovery_Pagination(t *testing.T) {
	var routers []apiRouter
	for i := 0; i < 250; i++ {
		routers = append(routers, apiRouter{
			Name:     "r" + strconv.Itoa(i) + "@docker",
			Provider: "docker",
			Status:   "enabled",
			Rule:     "Host(`h" + strconv.Itoa(i) + ".example.com`)",
		})
	}
	api := &fakeTraefikAPI{routers: routers}
	src := newAPISource(t, api, APIDiscoveryConfig{})

	hs, err := src.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(hs) != 250 {
		t.Fatalf("got %d hostnames across pages, want 250", len(hs))
	}
	if got := api.requests.Load(); got != 3 {
		t.Fatalf("made %d requests, want 3 pages", got)
	}
}

func TestAPIDiscovery_DeduplicatesAcrossRouters(t *testing.T) {
	api := &fakeTraefikAPI{routers: []apiRouter{
		{Name: "http@docker", Provider: "docker", Status: "enabled", Rule: "Host(`app.example.com`)", Using: []string{"web"}},
		{Name: "dup@docker", Provider: "docker", Status: "enabled", Rule: "Host(`app.example.com`)", Using: []string{"web"}},
		{Name: "https@docker", Provider: "docker", Status: "enabled", Rule: "Host(`app.example.com`)", Using: []string{"websecure"}},
	}}
	src := newAPISource(t, api, APIDiscoveryConfig{})
	hs, err := src.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	assertStrings(t, hostEntrypoints(hs), []string{"app.example.com|web", "app.example.com|websecure"})
}

func TestAPIDiscovery_BasePathAndBasicAuth(t *testing.T) {
	api := &fakeTraefikAPI{
		username: "dnsweaver",
		password: "s3cret",
		routers:  []apiRouter{{Name: "a@docker", Provider: "docker", Status: "enabled", Rule: "Host(`a.example.com`)"}},
	}

	src := newAPISource(t, api, APIDiscoveryConfig{URL: "/traefik/", Username: "dnsweaver", Password: "s3cret"})
	hs, err := src.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(hs) != 1 {
		t.Fatalf("got %d hostnames, want 1", len(hs))
	}
	if p := api.lastPath.Load(); p != "/traefik/api/http/routers" {
		t.Fatalf("requested path %v, want /traefik/api/http/routers", p)
	}

	wrong := newAPISource(t, api, APIDiscoveryConfig{Password: "wrong"})
	_, err = wrong.Discover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected HTTP 401 error, got %v", err)
	}
	if strings.Contains(err.Error(), "wrong") || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error leaks credentials: %v", err)
	}
}

func TestAPIDiscovery_Errors(t *testing.T) {
	tests := []struct {
		name    string
		api     *fakeTraefikAPI
		cfg     APIDiscoveryConfig
		wantErr string
	}{
		{name: "server error", api: failingAPI(http.StatusBadGateway), wantErr: "HTTP 502"},
		{name: "invalid json", api: &fakeTraefikAPI{body: "<html>dashboard</html>"}, wantErr: "decoding"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := newAPISource(t, tt.api, tt.cfg)
			hs, err := src.Discover(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Discover error = %v, want containing %q", err, tt.wantErr)
			}
			if hs != nil {
				t.Fatalf("expected no partial hostnames on error, got %v", hs)
			}
		})
	}

	t.Run("unreachable server", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		url := srv.URL
		srv.Close()
		src := New(WithLogger(testLogger()), WithAPIDiscovery(APIDiscoveryConfig{URL: url}))
		if _, err := src.Discover(context.Background()); err == nil {
			t.Fatal("expected error for unreachable API")
		}
	})

	t.Run("invalid url", func(t *testing.T) {
		src := New(WithLogger(testLogger()), WithAPIDiscovery(APIDiscoveryConfig{URL: "ftp://traefik:8080"}))
		_, err := src.Discover(context.Background())
		if err == nil || !strings.Contains(err.Error(), "misconfigured") {
			t.Fatalf("expected misconfiguration error, got %v", err)
		}
	})
}

func TestAPIDiscovery_CombinedWithFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "routes.yml"), []byte(
		"http:\n  routers:\n    static:\n      rule: \"Host(`static.example.com`) || Host(`shared.example.com`)\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	api := &fakeTraefikAPI{routers: []apiRouter{
		{Name: "app@docker", Provider: "docker", Status: "enabled", Rule: "Host(`app.example.com`) || Host(`shared.example.com`)"},
	}}
	src := newAPISource(t, api, APIDiscoveryConfig{}, WithFileDiscovery(source.FileDiscoveryConfig{FilePaths: []string{dir}}))

	hs, err := src.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	assertStrings(t, hostEntrypoints(hs), []string{"app.example.com|", "shared.example.com|", "static.example.com|"})

	// A failing API must fail the whole discovery, even though files are
	// readable, so the reconciler keeps existing records.
	api.status.Store(http.StatusServiceUnavailable)
	if hs, err := src.Discover(context.Background()); err == nil || hs != nil {
		t.Fatalf("expected error and no hostnames when API fails, got %v, %v", hs, err)
	}
}
