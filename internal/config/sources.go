package config

import (
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/maxfield-allison/dnsweaver/pkg/source"
)

// SourceInstanceConfig holds configuration for a single source instance.
// Sources are parsed from the DNSWEAVER_SOURCES environment variable.
type SourceInstanceConfig struct {
	// Name is the source type (e.g., "traefik", "caddy", "nginx").
	Name string

	// FileDiscovery contains file-based discovery configuration.
	// Presence of FilePaths implies enablement (per design in #22).
	FileDiscovery source.FileDiscoveryConfig

	// DefaultEntryPoints is a Traefik-source-specific setting that lists the
	// entrypoints an unlabeled router should be considered bound to. Mirrors
	// Traefik's `entryPoints.<name>.asDefault = true` configuration.
	// See sources/traefik.WithDefaultEntryPoints. Ignored for non-traefik sources.
	DefaultEntryPoints []string

	// API contains Traefik REST API discovery configuration.
	// Presence of URL implies enablement. Only valid for the traefik source.
	API TraefikAPIConfig
}

// DefaultTraefikAPIPollInterval is how often the Traefik API is polled when
// API discovery is enabled and no interval is configured.
const DefaultTraefikAPIPollInterval = 30 * time.Second

// DefaultTraefikAPIStartupSettle is how long Traefik must have been running
// before its router list is trusted as complete.
const DefaultTraefikAPIStartupSettle = 60 * time.Second

// DefaultTraefikAPIDropGrace is how long a suspicious drop in the Traefik
// router list is held back before hostnames may be removed.
const DefaultTraefikAPIDropGrace = 5 * time.Minute

// TraefikAPIConfig holds configuration for discovering routers through the
// Traefik REST API (GET /api/http/routers).
type TraefikAPIConfig struct {
	// URL is the base URL of the Traefik API (e.g. http://127.0.0.1:8080).
	// Empty means API discovery is disabled.
	URL string

	// Username and Password enable HTTP basic authentication.
	Username string
	Password string

	// ExcludeProviders lists Traefik providers whose routers are ignored.
	// nil means the source default ("internal"); an empty non-nil slice
	// excludes nothing.
	ExcludeProviders []string

	// TLSSkipVerify disables certificate verification for HTTPS URLs.
	TLSSkipVerify bool

	// PollInterval is how often the API is queried for changes.
	PollInterval time.Duration

	// DropGrace is how long a suspicious drop in the router list (a provider
	// vanishing, or the list shrinking by more than half) is held back before
	// hostnames may be removed. Zero disables the guard.
	DropGrace time.Duration

	// StartupSettle is how long Traefik must have been running (per
	// /api/version startDate) before its router list is trusted as complete.
	// Zero disables the guard.
	StartupSettle time.Duration

	// secretErr records a failure reading the password from a file so that
	// validation can report it instead of silently running unauthenticated.
	secretErr error
}

// IsEnabled returns true if Traefik API discovery is configured.
func (c TraefikAPIConfig) IsEnabled() bool {
	return c.URL != ""
}

// defaultTraefikAPIConfig returns the API config defaults.
func defaultTraefikAPIConfig() TraefikAPIConfig {
	return TraefikAPIConfig{PollInterval: DefaultTraefikAPIPollInterval, DropGrace: DefaultTraefikAPIDropGrace, StartupSettle: DefaultTraefikAPIStartupSettle}
}

// SourceConfig holds all source configuration.
type SourceConfig struct {
	// Sources is the ordered list of source instance names from DNSWEAVER_SOURCES.
	Names []string

	// Instances contains configuration for each source.
	Instances []*SourceInstanceConfig
}

// parseSources parses the DNSWEAVER_SOURCES environment variable.
// Returns the list of source names in order. Defaults to "traefik" if not set.
//
// For backward compatibility, DNSWEAVER_SOURCE (singular) is also accepted
// but deprecated. If DNSWEAVER_SOURCES is not set but DNSWEAVER_SOURCE is,
// the singular value is used as a single-element source list.
func parseSources() []string {
	sourcesStr := getEnv("DNSWEAVER_SOURCES")
	if sourcesStr == "" {
		// Fall back to deprecated DNSWEAVER_SOURCE (singular)
		if sourceStr := getEnv("DNSWEAVER_SOURCE"); sourceStr != "" {
			slog.Warn("DNSWEAVER_SOURCE is deprecated, use DNSWEAVER_SOURCES instead")
			sourcesStr = sourceStr
		} else {
			// Default to traefik for backward compatibility
			return []string{"traefik"}
		}
	}

	var sources []string
	for _, s := range strings.Split(sourcesStr, ",") {
		s = strings.TrimSpace(s)
		s = strings.ToLower(s)
		if s != "" {
			sources = append(sources, s)
		}
	}
	return sources
}

// loadSourceConfig loads source-specific configuration from environment variables.
//
// Environment variable patterns:
//
//	DNSWEAVER_SOURCE_TRAEFIK_FILE_PATHS=/rules,/config/traefik
//	DNSWEAVER_SOURCE_TRAEFIK_FILE_PATTERN=*.yml,*.yaml
//	DNSWEAVER_SOURCE_TRAEFIK_POLL_INTERVAL=30s
//	DNSWEAVER_SOURCE_TRAEFIK_WATCH_METHOD=auto
//	DNSWEAVER_SOURCE_TRAEFIK_API_URL=http://127.0.0.1:8080
func loadSourceConfig() *SourceConfig {
	names := parseSources()

	cfg := &SourceConfig{
		Names:     names,
		Instances: make([]*SourceInstanceConfig, 0, len(names)),
	}

	for _, name := range names {
		inst := loadSourceInstanceConfig(name)
		cfg.Instances = append(cfg.Instances, inst)
	}

	return cfg
}

// sourceEnvPrefix returns the environment variable prefix for a source.
// Example: "traefik" -> "DNSWEAVER_SOURCE_TRAEFIK_"
func sourceEnvPrefix(name string) string {
	return "DNSWEAVER_SOURCE_" + strings.ToUpper(name) + "_"
}

// loadSourceInstanceConfig loads configuration for a single source.
func loadSourceInstanceConfig(name string) *SourceInstanceConfig {
	cfg := &SourceInstanceConfig{
		Name:          name,
		FileDiscovery: source.DefaultFileDiscoveryConfig(),
		API:           defaultTraefikAPIConfig(),
	}

	applySourceEnv(cfg)
	return cfg
}

// applySourceEnv preserves YAML discovery settings unless an environment
// override is supplied, using the same parser as env-only source loading.
func applySourceEnv(cfg *SourceInstanceConfig) {
	prefix := sourceEnvPrefix(cfg.Name)

	// FILE_PATHS - comma-separated list of paths to watch
	// Per design: presence implies enablement (no ENABLED flag needed)
	if pathsStr := getEnv(prefix + "FILE_PATHS"); pathsStr != "" {
		var paths []string
		for _, p := range strings.Split(pathsStr, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				paths = append(paths, p)
			}
		}
		cfg.FileDiscovery.FilePaths = paths
	}

	// FILE_PATTERN - glob pattern for files to include
	// If not set, source-specific defaults apply (e.g., "*.yml,*.yaml" for traefik)
	if pattern := getEnv(prefix + "FILE_PATTERN"); pattern != "" {
		cfg.FileDiscovery.FilePattern = pattern
	}

	// POLL_INTERVAL - how often to check files for changes (default: 60s)
	if intervalStr := getEnv(prefix + "POLL_INTERVAL"); intervalStr != "" {
		if interval, err := time.ParseDuration(intervalStr); err == nil && interval >= time.Second {
			cfg.FileDiscovery.PollInterval = interval
		}
		// Silently use default for invalid values (per config design)
	}

	// WATCH_METHOD - auto, inotify, poll (default: auto)
	if method := getEnv(prefix + "WATCH_METHOD"); method != "" {
		cfg.FileDiscovery.WatchMethod = strings.ToLower(method)
	}

	// DEFAULT_ENTRYPOINTS - traefik-only: which entrypoints unlabeled routers
	// should be treated as bound to (mirrors Traefik's `asDefault` setting).
	// Comma-separated, whitespace tolerant. Empty/unset preserves wildcard behavior.
	if eps := getEnv(prefix + "DEFAULT_ENTRYPOINTS"); eps != "" {
		var out []string
		for _, e := range strings.Split(eps, ",") {
			e = strings.TrimSpace(e)
			if e != "" {
				out = append(out, e)
			}
		}
		cfg.DefaultEntryPoints = out
	}

	applySourceAPIEnv(cfg, prefix)
}

// applySourceAPIEnv applies the API_* environment overrides. These are only
// meaningful for the traefik source; validation rejects them elsewhere.
//
//	API_URL               base URL of the Traefik API (enables API discovery)
//	API_USERNAME          basic auth user
//	API_PASSWORD(_FILE)   basic auth password, or a file containing it
//	API_EXCLUDE_PROVIDERS comma-separated providers to ignore (default: internal;
//	                      set to an empty value to include every provider)
//	API_TLS_SKIP_VERIFY   skip TLS certificate verification
//	API_POLL_INTERVAL     how often to query the API (default: 30s, minimum 1s)
//	API_DROP_GRACE        hold suspicious router drops this long (default: 5m; 0 disables)
//	API_STARTUP_SETTLE    distrust the list until Traefik has run this long (default: 60s; 0 disables)
func applySourceAPIEnv(cfg *SourceInstanceConfig, prefix string) {
	if v := getEnv(prefix + "API_URL"); v != "" {
		cfg.API.URL = strings.TrimSpace(v)
	}
	if v := getEnv(prefix + "API_USERNAME"); v != "" {
		cfg.API.Username = v
	}
	if password, configured, err := getEnvWithFileFallback(prefix, "API_PASSWORD"); err != nil {
		cfg.API.secretErr = err
	} else if configured {
		cfg.API.Password = password
	}
	if v, ok := os.LookupEnv(prefix + "API_EXCLUDE_PROVIDERS"); ok {
		providers := splitCommaList(v)
		if providers == nil {
			providers = []string{}
		}
		cfg.API.ExcludeProviders = providers
	}
	if v := getEnv(prefix + "API_TLS_SKIP_VERIFY"); v != "" {
		cfg.API.TLSSkipVerify = parseBool(v, false)
	}
	if v := getEnv(prefix + "API_POLL_INTERVAL"); v != "" {
		if interval, err := time.ParseDuration(v); err == nil && interval >= time.Second {
			cfg.API.PollInterval = interval
		}
	}
	if v := getEnv(prefix + "API_DROP_GRACE"); v != "" {
		if grace, ok := parseDropGrace(v); ok {
			cfg.API.DropGrace = grace
		}
	}
	if v := getEnv(prefix + "API_STARTUP_SETTLE"); v != "" {
		if settle, ok := parseDropGrace(v); ok {
			cfg.API.StartupSettle = settle
		}
	}
}

// parseDropGrace parses a guard duration (API_DROP_GRACE, API_STARTUP_SETTLE).
// "0" (or any zero duration) disables the guard; negative or malformed values
// are rejected so the default is kept.
func parseDropGrace(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "0" {
		return 0, true
	}
	grace, err := time.ParseDuration(v)
	if err != nil || grace < 0 {
		return 0, false
	}
	return grace, true
}

// GetSourceInstance returns the configuration for a specific source by name.
func (c *SourceConfig) GetSourceInstance(name string) *SourceInstanceConfig {
	for _, inst := range c.Instances {
		if inst.Name == name {
			return inst
		}
	}
	return nil
}

// HasFileDiscovery returns true if any source has file discovery configured.
func (c *SourceConfig) HasFileDiscovery() bool {
	for _, inst := range c.Instances {
		if inst.FileDiscovery.IsEnabled() {
			return true
		}
	}
	return false
}

// HasAPIDiscovery returns true if any source has Traefik API discovery configured.
func (c *SourceConfig) HasAPIDiscovery() bool {
	for _, inst := range c.Instances {
		if inst.API.IsEnabled() {
			return true
		}
	}
	return false
}

// HasDiscovery returns true if any source needs periodic discovery polling
// (file discovery or Traefik API discovery).
func (c *SourceConfig) HasDiscovery() bool {
	return c.HasFileDiscovery() || c.HasAPIDiscovery()
}

// DiscoveryPollInterval returns the polling interval for periodic discovery:
// the shortest configured interval among enabled file and API discovery
// settings. Returns 0 if no discovery is enabled.
func (c *SourceConfig) DiscoveryPollInterval() time.Duration {
	var shortest time.Duration
	consider := func(d time.Duration) {
		if d > 0 && (shortest == 0 || d < shortest) {
			shortest = d
		}
	}
	for _, inst := range c.Instances {
		if inst.FileDiscovery.IsEnabled() {
			consider(inst.FileDiscovery.PollInterval)
		}
		if inst.API.IsEnabled() {
			consider(inst.API.PollInterval)
		}
	}
	return shortest
}
