package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestSourceAPIEnv(t *testing.T) {
	clearAllEnv(t)
	defer clearAllEnv(t)

	secret := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(secret, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DNSWEAVER_SOURCES", "traefik")
	t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_URL", " http://127.0.0.1:8080 ")
	t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_USERNAME", "dnsweaver")
	t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_PASSWORD", "ignored-when-file-set")
	t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_PASSWORD_FILE", secret)
	t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_EXCLUDE_PROVIDERS", "internal, file")
	t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_TLS_SKIP_VERIFY", "true")
	t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_POLL_INTERVAL", "15s")

	api := loadSourceConfig().GetSourceInstance("traefik").API
	if api.URL != "http://127.0.0.1:8080" || api.Username != "dnsweaver" || api.Password != "from-file" ||
		!reflect.DeepEqual(api.ExcludeProviders, []string{"internal", "file"}) || !api.TLSSkipVerify ||
		api.PollInterval != 15*time.Second || api.secretErr != nil {
		t.Fatalf("unexpected API config: %+v", api)
	}
}

func TestSourceAPIEnvDefaults(t *testing.T) {
	clearAllEnv(t)
	defer clearAllEnv(t)
	t.Setenv("DNSWEAVER_SOURCES", "traefik")

	cfg := loadSourceConfig()
	api := cfg.GetSourceInstance("traefik").API
	if api.IsEnabled() || api.ExcludeProviders != nil || api.PollInterval != DefaultTraefikAPIPollInterval {
		t.Fatalf("unexpected default API config: %+v", api)
	}
	if cfg.HasDiscovery() || cfg.DiscoveryPollInterval() != 0 {
		t.Fatal("discovery must be disabled without file paths or API URL")
	}
}

func TestSourceAPIEnvEmptyExcludeIncludesEverything(t *testing.T) {
	clearAllEnv(t)
	defer clearAllEnv(t)
	t.Setenv("DNSWEAVER_SOURCES", "traefik")
	t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_URL", "http://traefik:8080")
	t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_EXCLUDE_PROVIDERS", "")

	api := loadSourceConfig().GetSourceInstance("traefik").API
	if api.ExcludeProviders == nil || len(api.ExcludeProviders) != 0 {
		t.Fatalf("empty EXCLUDE_PROVIDERS must yield an empty non-nil list, got %#v", api.ExcludeProviders)
	}
}

func TestSourceAPIEnvInvalidPollIntervalKeepsDefault(t *testing.T) {
	clearAllEnv(t)
	defer clearAllEnv(t)
	t.Setenv("DNSWEAVER_SOURCES", "traefik")
	t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_URL", "http://traefik:8080")
	for _, v := range []string{"soon", "500ms"} {
		t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_POLL_INTERVAL", v)
		if got := loadSourceConfig().GetSourceInstance("traefik").API.PollInterval; got != DefaultTraefikAPIPollInterval {
			t.Fatalf("POLL_INTERVAL=%q gave %v, want default", v, got)
		}
	}
}

func TestSourceAPIEnvMissingPasswordFile(t *testing.T) {
	clearAllEnv(t)
	defer clearAllEnv(t)
	t.Setenv("DNSWEAVER_SOURCES", "traefik")
	t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_URL", "http://traefik:8080")
	t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_PASSWORD_FILE", filepath.Join(t.TempDir(), "missing"))

	inst := loadSourceConfig().GetSourceInstance("traefik")
	errs := validateSourceAPI(inst)
	if len(errs) != 1 || !strings.Contains(errs[0].Field, "API_PASSWORD") {
		t.Fatalf("expected one API_PASSWORD error, got %v", errs)
	}
}

func TestFileSourceAPIYAML(t *testing.T) {
	clearAllEnv(t)
	defer clearAllEnv(t)

	secret := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(secret, []byte("yaml-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := `
sources:
  - name: traefik
    api:
      url: https://traefik.example.com/base
      username: dnsweaver
      password_file: ` + secret + `
      exclude_providers: []
      tls_skip_verify: true
      poll_interval: 20s
`
	var fc FileConfig
	if err := yaml.Unmarshal([]byte(doc), &fc); err != nil {
		t.Fatal(err)
	}
	api := convertFileSources(fc.Sources).GetSourceInstance("traefik").API
	if api.URL != "https://traefik.example.com/base" || api.Username != "dnsweaver" || api.Password != "yaml-secret" ||
		api.ExcludeProviders == nil || len(api.ExcludeProviders) != 0 || !api.TLSSkipVerify || api.PollInterval != 20*time.Second {
		t.Fatalf("unexpected API config from YAML: %+v", api)
	}
}

func TestFileSourceAPIEnvOverridesYAML(t *testing.T) {
	clearAllEnv(t)
	defer clearAllEnv(t)
	t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_URL", "http://override:8080")
	t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_POLL_INTERVAL", "5s")

	cfg := convertFileSources([]FileSourceConfig{{
		Name: "traefik",
		API:  &FileTraefikAPIConfig{URL: "http://file:8080", Username: "kept", PollInterval: "40s"},
	}})
	api := cfg.GetSourceInstance("traefik").API
	if api.URL != "http://override:8080" || api.Username != "kept" || api.PollInterval != 5*time.Second || api.ExcludeProviders != nil {
		t.Fatalf("env overrides not applied over YAML: %+v", api)
	}
}

func TestLoadYAMLWithTraefikAPIInterpolatesPassword(t *testing.T) {
	clearAllEnv(t)
	defer clearAllEnv(t)
	path := filepath.Join(t.TempDir(), "config.yml")
	doc := "sources:\n  - name: traefik\n    api:\n      url: http://127.0.0.1:8080\n      username: u\n      password: ${TRAEFIK_API_TEST_PW}\n" +
		"providers:\n  - name: dns\n    type: technitium\n    target: 10.0.0.1\n    domains: ['*.example.com']\n    config:\n      url: http://dns:5380\n      token: t\n      zone: example.com\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DNSWEAVER_CONFIG", path)
	t.Setenv("TRAEFIK_API_TEST_PW", "interpolated")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	api := cfg.GetSourceInstance("traefik").API
	if api.Password != "interpolated" || !cfg.HasDiscovery() || cfg.DiscoveryPollInterval() != DefaultTraefikAPIPollInterval {
		t.Fatalf("unexpected loaded API config: %+v", api)
	}
}

func TestDiscoveryPollIntervalUsesShortestEnabled(t *testing.T) {
	cfg := &SourceConfig{Instances: []*SourceInstanceConfig{
		{Name: "traefik", API: TraefikAPIConfig{URL: "http://t:8080", PollInterval: 45 * time.Second}},
		{Name: "caddy"}, // disabled discovery must not contribute
	}}
	cfg.Instances[1].FileDiscovery.PollInterval = time.Second
	if got := cfg.DiscoveryPollInterval(); got != 45*time.Second {
		t.Fatalf("got %v, want 45s from the only enabled source", got)
	}

	cfg.Instances[1].FileDiscovery.FilePaths = []string{"/rules"}
	cfg.Instances[1].FileDiscovery.PollInterval = 10 * time.Second
	if got := cfg.DiscoveryPollInterval(); got != 10*time.Second {
		t.Fatalf("got %v, want shortest enabled interval 10s", got)
	}
	if !cfg.HasAPIDiscovery() || !cfg.HasFileDiscovery() || !cfg.HasDiscovery() {
		t.Fatal("expected API and file discovery to be reported")
	}
}

func TestValidateSourceAPI(t *testing.T) {
	tests := []struct {
		name    string
		inst    SourceInstanceConfig
		wantErr string // empty = valid
	}{
		{name: "disabled", inst: SourceInstanceConfig{Name: "traefik"}},
		{name: "valid http", inst: SourceInstanceConfig{Name: "traefik", API: TraefikAPIConfig{URL: "http://127.0.0.1:8080"}}},
		{name: "valid https with path", inst: SourceInstanceConfig{Name: "traefik", API: TraefikAPIConfig{URL: "https://traefik.example.com/base"}}},
		{name: "other source", inst: SourceInstanceConfig{Name: "caddy", API: TraefikAPIConfig{URL: "http://t:8080"}}, wantErr: "not supported"},
		{name: "bad scheme", inst: SourceInstanceConfig{Name: "traefik", API: TraefikAPIConfig{URL: "ftp://t:8080"}}, wantErr: "scheme"},
		{name: "no host", inst: SourceInstanceConfig{Name: "traefik", API: TraefikAPIConfig{URL: "http://"}}, wantErr: "no host"},
		{name: "credentials in url", inst: SourceInstanceConfig{Name: "traefik", API: TraefikAPIConfig{URL: "http://u:p@t:8080"}}, wantErr: "credentials"},
		{name: "query in url", inst: SourceInstanceConfig{Name: "traefik", API: TraefikAPIConfig{URL: "http://t:8080/?x=1"}}, wantErr: "query"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := tt.inst
			errs := validateSourceAPI(&inst)
			if tt.wantErr == "" {
				if len(errs) != 0 {
					t.Fatalf("expected no errors, got %v", errs)
				}
				return
			}
			if len(errs) != 1 || !strings.Contains(errs[0].Message, tt.wantErr) {
				t.Fatalf("expected one error containing %q, got %v", tt.wantErr, errs)
			}
		})
	}
}

func TestSourceAPIDropGrace(t *testing.T) {
	tests := []struct {
		name string
		env  string // "" = unset
		yaml string // "" = unset
		want time.Duration
	}{
		{name: "default", want: DefaultTraefikAPIDropGrace},
		{name: "env duration", env: "2m", want: 2 * time.Minute},
		{name: "env zero disables", env: "0", want: 0},
		{name: "env negative keeps default", env: "-1m", want: DefaultTraefikAPIDropGrace},
		{name: "env malformed keeps default", env: "soon", want: DefaultTraefikAPIDropGrace},
		{name: "yaml duration", yaml: "90s", want: 90 * time.Second},
		{name: "yaml zero disables", yaml: "0s", want: 0},
		{name: "env overrides yaml", yaml: "90s", env: "10m", want: 10 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearAllEnv(t)
			defer clearAllEnv(t)
			if tt.env != "" {
				t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_DROP_GRACE", tt.env)
			}
			cfg := convertFileSources([]FileSourceConfig{{
				Name: "traefik",
				API:  &FileTraefikAPIConfig{URL: "http://traefik:8080", DropGrace: tt.yaml},
			}})
			if got := cfg.GetSourceInstance("traefik").API.DropGrace; got != tt.want {
				t.Fatalf("DropGrace = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSourceAPIStartupSettle(t *testing.T) {
	tests := []struct {
		name, env, yaml string
		want            time.Duration
	}{
		{name: "default", want: DefaultTraefikAPIStartupSettle},
		{name: "env duration", env: "2m", want: 2 * time.Minute},
		{name: "env zero disables", env: "0", want: 0},
		{name: "env negative keeps default", env: "-5s", want: DefaultTraefikAPIStartupSettle},
		{name: "yaml duration", yaml: "45s", want: 45 * time.Second},
		{name: "env overrides yaml", yaml: "45s", env: "90s", want: 90 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearAllEnv(t)
			defer clearAllEnv(t)
			if tt.env != "" {
				t.Setenv("DNSWEAVER_SOURCE_TRAEFIK_API_STARTUP_SETTLE", tt.env)
			}
			cfg := convertFileSources([]FileSourceConfig{{
				Name: "traefik",
				API:  &FileTraefikAPIConfig{URL: "http://traefik:8080", StartupSettle: tt.yaml},
			}})
			if got := cfg.GetSourceInstance("traefik").API.StartupSettle; got != tt.want {
				t.Fatalf("StartupSettle = %v, want %v", got, tt.want)
			}
		})
	}
}
