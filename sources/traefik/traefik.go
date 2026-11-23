// Package traefik provides a Source implementation for extracting hostnames
// from Traefik reverse proxy labels and static configuration files.
//
// This package parses Docker container labels in the format used by Traefik v2/v3
// to configure HTTP routers, static YAML/TOML configuration files, and the
// routers Traefik reports through its REST API (GET /api/http/routers).
//
// Example labels:
//
//	traefik.http.routers.myapp.rule=Host(`app.example.com`)
//	traefik.http.routers.myapp.rule=Host(`app.example.com`) || Host(`www.example.com`)
//	traefik.http.routers.myapp.rule=Host(`app.example.com`) && PathPrefix(`/api`)
//
// Example static file (YAML):
//
//	http:
//	  routers:
//	    myapp:
//	      rule: "Host(`app.example.com`)"
package traefik

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/maxfield-allison/dnsweaver/pkg/httputil"
	"github.com/maxfield-allison/dnsweaver/pkg/source"
	"github.com/maxfield-allison/dnsweaver/pkg/workload"
)

const sourceName = "traefik"

// DefaultFilePattern is the default glob pattern for Traefik config files.
// Includes YAML (.yml, .yaml) and TOML (.toml) formats.
const DefaultFilePattern = "*.yml,*.yaml,*.toml"

// Traefik implements the source.Source interface for extracting hostnames
// from Traefik container labels and static configuration files.
type Traefik struct {
	parser             *Parser
	logger             *slog.Logger
	fileConfig         source.FileDiscoveryConfig
	apiConfig          APIDiscoveryConfig
	api                *apiClient
	apiErr             error // invalid API configuration, reported by Discover
	defaultEntryPoints []string
}

// Option is a functional option for configuring Traefik.
type Option func(*Traefik)

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(t *Traefik) {
		t.logger = logger
	}
}

// WithFileDiscovery configures file-based discovery.
func WithFileDiscovery(config source.FileDiscoveryConfig) Option {
	return func(t *Traefik) {
		t.fileConfig = config
		// Apply default file pattern if not set
		if t.fileConfig.FilePattern == "" {
			t.fileConfig.FilePattern = DefaultFilePattern
		}
	}
}

// WithAPIDiscovery configures discovery from the Traefik REST API.
// Discovery is enabled when config.URL is non-empty.
func WithAPIDiscovery(config APIDiscoveryConfig) Option {
	return func(t *Traefik) {
		t.apiConfig = config
	}
}

// WithDefaultEntryPoints configures which entrypoints should be assumed for
// Traefik routers that declare no `entryPoints` (label or static config).
//
// Mirrors Traefik's `entryPoints.<name>.asDefault = true` setting: when set
// in Traefik, undeclared routers bind only to the `asDefault` entrypoints,
// not to all entrypoints. dnsweaver cannot read Traefik's static config so
// this must be supplied explicitly via
// `DNSWEAVER_SOURCE_TRAEFIK_DEFAULT_ENTRYPOINTS`.
//
// Empty/unset preserves pre-1.4.2 wildcard behavior.
func WithDefaultEntryPoints(eps []string) Option {
	return func(t *Traefik) {
		t.defaultEntryPoints = eps
	}
}

// New creates a new Traefik source.
func New(opts ...Option) *Traefik {
	t := &Traefik{
		logger:     slog.Default(),
		fileConfig: source.DefaultFileDiscoveryConfig(),
	}

	for _, opt := range opts {
		opt(t)
	}

	parserOpts := []ParserOption{WithParserLogger(t.logger)}
	if len(t.defaultEntryPoints) > 0 {
		parserOpts = append(parserOpts, WithParserDefaultEntryPoints(t.defaultEntryPoints))
	}
	t.parser = NewParser(parserOpts...)

	if t.apiConfig.IsEnabled() {
		httpClient := t.apiConfig.HTTPClient
		if httpClient == nil {
			timeout := t.apiConfig.Timeout
			if timeout <= 0 {
				timeout = DefaultAPITimeout
			}
			httpClient = httputil.NewClient(&httputil.ClientConfig{
				Timeout:       timeout,
				TLSSkipVerify: t.apiConfig.TLSSkipVerify,
				Logger:        t.logger,
			})
		}
		t.api, t.apiErr = newAPIClient(t.apiConfig, httpClient)
	}

	return t
}

// Name returns the source identifier.
func (t *Traefik) Name() string {
	return sourceName
}

// Extract parses Traefik labels and returns discovered hostnames.
//
// This method looks for traefik.http.routers.*.rule labels and extracts
// all Host() patterns from the rule values. Multiple hostnames from the
// same rule are returned as separate Hostname entries.
//
// Returns an empty slice if no Traefik labels are found.
// Never returns an error - malformed rules are logged and skipped.
func (t *Traefik) Extract(ctx context.Context, w workload.Workload) ([]source.Hostname, error) {
	if len(w.Labels) == 0 {
		return nil, nil
	}

	extractions := t.parser.ExtractHostnames(w.Labels)

	hostnames := make([]source.Hostname, 0, len(extractions))
	for _, e := range extractions {
		hostnames = append(hostnames, source.Hostname{
			Name:     e.Hostname,
			Source:   sourceName,
			Router:   e.Router,
			Metadata: entryPointMetadata(e.EntryPoint),
		})
	}

	if len(hostnames) > 0 {
		t.logger.Debug("extracted hostnames from traefik labels",
			slog.Int("count", len(hostnames)),
		)
	}

	return hostnames, nil
}

// Discover finds hostnames from Traefik static configuration files and/or
// the Traefik REST API, whichever are configured.
//
// File discovery parses YAML/TOML files for http.routers.*.rule entries; it
// ONLY parses router rules - middleware files, service definitions, and other
// config sections are safely ignored. API discovery reads the routers Traefik
// actually built (GET /api/http/routers), which includes routers generated
// from a provider's defaultRule.
//
// If either configured method fails, Discover returns an error and no
// hostnames, so the reconciler treats the snapshot as incomplete and keeps
// existing records instead of deleting them.
//
// Returns nil, nil if neither discovery method is configured.
func (t *Traefik) Discover(ctx context.Context) ([]source.Hostname, error) {
	if !t.SupportsDiscovery() {
		return nil, nil
	}

	var extractions []HostnameExtraction

	if t.fileConfig.IsEnabled() {
		t.logger.Debug("discovering hostnames from traefik files",
			slog.Any("paths", t.fileConfig.FilePaths),
			slog.String("pattern", t.fileConfig.FilePattern),
		)
		fromFiles, err := t.parser.DiscoverFromFiles(ctx, t.fileConfig.FilePaths, t.fileConfig.FilePattern)
		if err != nil {
			return nil, err
		}
		extractions = append(extractions, fromFiles...)
	}

	if t.apiConfig.IsEnabled() {
		if t.apiErr != nil {
			return nil, fmt.Errorf("traefik api discovery misconfigured: %w", t.apiErr)
		}
		fromAPI, err := t.parser.DiscoverFromAPI(ctx, t.api)
		if err != nil {
			return nil, err
		}
		extractions = append(extractions, fromAPI...)
	}

	// Convert to source.Hostname, deduplicating (hostname, entrypoint) pairs
	// that both files and the API report.
	type seenKey struct {
		hostname   string
		entrypoint string
	}
	seen := make(map[seenKey]struct{}, len(extractions))
	result := make([]source.Hostname, 0, len(extractions))
	for _, e := range extractions {
		k := seenKey{hostname: e.Hostname, entrypoint: e.EntryPoint}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		result = append(result, source.Hostname{
			Name:     e.Hostname,
			Source:   sourceName,
			Router:   e.Router,
			Metadata: entryPointMetadata(e.EntryPoint),
		})
	}

	if len(result) > 0 {
		t.logger.Debug("discovered hostnames from traefik files/api",
			slog.Int("count", len(result)),
		)
	}

	return result, nil
}

// SupportsDiscovery returns true if file paths or an API URL are configured.
func (t *Traefik) SupportsDiscovery() bool {
	return t.fileConfig.IsEnabled() || t.apiConfig.IsEnabled()
}

// SupportsAPIDiscovery returns true if an API URL is configured.
func (t *Traefik) SupportsAPIDiscovery() bool {
	return t.apiConfig.IsEnabled()
}

// SupportedPlatforms returns an empty slice, meaning Traefik source works with
// all platforms. Docker labels and K8s annotations both use the same format.
func (t *Traefik) SupportedPlatforms() []workload.Platform {
	return nil
}

// FileConfig returns the file discovery configuration.
func (t *Traefik) FileConfig() source.FileDiscoveryConfig {
	return t.fileConfig
}

// Ensure Traefik implements source.Source
var _ source.Source = (*Traefik)(nil)

// entryPointMetadata returns a Metadata map carrying the traefik entrypoint,
// or nil when the extraction is wildcard-bound (no entrypoint declared).
// Returning nil for the wildcard case preserves Hostname.Matches semantics:
// MatchingProvidersForHostname treats a missing key as “matches every
// filter”, which mirrors Traefik's own “undeclared = bound to all
// entrypoints” behavior and keeps backward compatibility for users who
// don't opt into DNSWEAVER_{NAME}_ENTRYPOINTS.
func entryPointMetadata(entrypoint string) map[string]string {
	if entrypoint == "" {
		return nil
	}
	return map[string]string{MetadataKeyEntryPoint: entrypoint}
}
