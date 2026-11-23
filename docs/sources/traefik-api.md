---
title: Traefik API Source
description: dnsweaver reads the routers Traefik actually built from its REST API, including routers generated from a provider defaultRule, to manage DNS records.
---

# Traefik API

dnsweaver can discover hostnames from the routers Traefik reports through its
REST API (`GET /api/http/routers`), instead of parsing labels or files.

The API returns the routers Traefik actually built, so this covers cases that
label and file parsing cannot see:

- Containers without a `Host()` label that get a router from the Docker
  provider's [`defaultRule`](https://doc.traefik.io/traefik/providers/docker/#defaultrule)
- Routers from any Traefik provider (Docker, Swarm, file, Kubernetes CRDs,
  Consul, ...) through a single integration
- Routers whose entrypoints were resolved by Traefik from `asDefault`
  entrypoints

## Configuration

API discovery is part of the `traefik` source. Setting the API URL turns it on:

```yaml
environment:
  - DNSWEAVER_SOURCES=traefik
  - DNSWEAVER_SOURCE_TRAEFIK_API_URL=http://127.0.0.1:8080
  - DNSWEAVER_SOURCE_TRAEFIK_API_POLL_INTERVAL=30s
```

Or in the YAML configuration file:

```yaml
sources:
  - name: traefik
    api:
      url: http://127.0.0.1:8080
      poll_interval: 30s
      # username: dnsweaver
      # password: ${TRAEFIK_API_PASSWORD}   # or password_file: /run/secrets/traefik_api
      # exclude_providers: [internal]       # default; [] includes every provider
      # tls_skip_verify: false
```

API discovery can be combined with label parsing and with
[file discovery](traefik-files.md). Hostnames reported by more than one method
are deduplicated.

## Configuration Reference

| Variable | YAML (`sources[].api`) | Default | Description |
|----------|------------------------|---------|-------------|
| `DNSWEAVER_SOURCE_TRAEFIK_API_URL` | `url` | *(none)* | Base URL of the Traefik API. `/api/http/routers` is appended, so a path prefix is kept. Setting it enables API discovery. |
| `DNSWEAVER_SOURCE_TRAEFIK_API_USERNAME` | `username` | *(none)* | HTTP basic auth user, for an API exposed behind a `basicAuth` middleware |
| `DNSWEAVER_SOURCE_TRAEFIK_API_PASSWORD` | `password` | *(none)* | HTTP basic auth password. `_FILE` variant supported (`password_file` in YAML). |
| `DNSWEAVER_SOURCE_TRAEFIK_API_EXCLUDE_PROVIDERS` | `exclude_providers` | `internal` | Comma-separated Traefik providers whose routers are ignored. Set it to an empty value (`[]` in YAML) to include every provider. |
| `DNSWEAVER_SOURCE_TRAEFIK_API_TLS_SKIP_VERIFY` | `tls_skip_verify` | `false` | Skip certificate verification for an `https://` API URL |
| `DNSWEAVER_SOURCE_TRAEFIK_API_POLL_INTERVAL` | `poll_interval` | `30s` | How often the API is queried (minimum `1s`) |

Credentials must not be embedded in the URL; use the username and password
settings so they are never logged.

## What is discovered

For every router returned by the API, dnsweaver:

1. Skips routers whose `status` is not `enabled` (Traefik reports `disabled`
   or `warning` for routers it does not serve).
2. Skips routers from excluded providers. By default this is `internal`
   (`api@internal`, `dashboard@internal`, redirect routers, ...).
3. Extracts every `` Host(`...`) `` matcher from the rule, including rules with
   whitespace such as `` Host( `app.example.com` ) ``. `HostRegexp` and
   `HostSNI` matchers are ignored, as with labels and files.
4. Binds each hostname to the router's effective entrypoints (`using`), falling
   back to its declared `entryPoints`, then to
   `DNSWEAVER_SOURCE_TRAEFIK_DEFAULT_ENTRYPOINTS`, then to every entrypoint.
   Per-instance `DNSWEAVER_{NAME}_ENTRYPOINTS` filters work the same way as for
   labels.

TCP and UDP routers are not read: TCP routers on plain-TCP entrypoints use
`` HostSNI(`*`) `` and UDP routers have no rule, so there is no hostname to
extract. Use [native labels](native-labels.md) (`dnsweaver.hostname`) for
those services.

## Change detection

Traefik's API has no change stream, so dnsweaver combines two triggers:

- **Docker events.** A container start, stop or removal triggers a
  reconciliation (after the usual 2-second debounce), and every reconciliation
  queries the API. In practice the new router is already in the API by then,
  so DNS follows within a couple of seconds.
- **Polling.** The API is also queried every `poll_interval`, which catches
  changes that do not come from Docker events (file provider, other providers)
  and any router Traefik had not published yet when the event-driven
  reconciliation ran.

## Failure handling

If the API is unreachable, returns a non-200 status, or returns a body that is
not a router list, discovery fails for that cycle. The reconciler then treats
its view as incomplete and **does not delete any records**; it resumes normal
operation once the API answers again. A paginated listing is only used when
every page was fetched successfully.

## Reaching the API

dnsweaver needs network access to the Traefik API:

- With Traefik on `network_mode: host` and `api.insecure: true`, run dnsweaver
  with `network_mode: host` too and use `http://127.0.0.1:8080`.
- With Traefik on a Docker network, put dnsweaver on the same network and use
  `http://traefik:8080`.
- With the API published through a router (`api@internal` behind
  `basicAuth`), use its HTTPS URL plus `API_USERNAME` / `API_PASSWORD`.

The API only needs read access; dnsweaver issues `GET` requests exclusively.
