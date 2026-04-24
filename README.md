# ebpf-firewall-k8s

[![Release](https://github.com/Cloud-Exit/ebpf-firewall/actions/workflows/release.yml/badge.svg?branch=main)](https://github.com/Cloud-Exit/ebpf-firewall/actions/workflows/release.yml)
[![Last commit](https://img.shields.io/github/last-commit/Cloud-Exit/ebpf-firewall/main)](https://github.com/Cloud-Exit/ebpf-firewall/commits/main)

`ebpf-firewall-k8s` is a node-local Kubernetes firewall daemon that uses eBPF TC ingress filters to allow protected TCP and UDP traffic only from approved IPv4 sources.

The daemon runs as a privileged DaemonSet, attaches an eBPF classifier to configured host interfaces, and keeps its allowlist in eBPF maps. Configuration is provided through a mounted ConfigMap directory and is polled on a refresh interval, so updates are picked up without talking to the Kubernetes API.

## What It Does

- Protects selected TCP/UDP destination ports, or every TCP/UDP port.
- Allows traffic when the source IPv4 address matches an allowlist entry.
- Supports individual IPv4 addresses and CIDR ranges.
- Fetches allowlists from `http://`, `https://`, or `file://` sources.
- Attaches to host interfaces by exact name or glob, such as `eth0`, `cni0`, or `veth*`.
- Runs through a Helm chart as a Kubernetes DaemonSet.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `cmd/ebpf-firewall` | Daemon entrypoint. |
| `internal/allowlist` | Allowlist fetch and parse logic. |
| `internal/config` | ConfigMap and environment variable loading. |
| `internal/firewall` | eBPF maps, TC attachment, and packet filter program. |
| `charts/ebpf-firewall` | Helm chart for Kubernetes deployment. |
| `test/e2e` | Kind-based end-to-end test fixtures and helper server. |

## Requirements

For development:

- Go 1.24 or newer.
- Helm.
- Docker or a Docker-compatible runtime for image builds and Kind e2e runs.
- Kind and kubectl for e2e testing.

For Kubernetes nodes:

- Linux nodes with eBPF and TC support.
- Permission to run a privileged DaemonSet.
- Kernel and container runtime support for the `NET_ADMIN`, `BPF`, `PERFMON`, and `SYS_RESOURCE` capabilities.

## Build And Test

Run unit tests:

```bash
make test
```

Build the daemon binary:

```bash
make build
```

Build the container image:

```bash
make docker-build
```

Validate the Helm chart:

```bash
make helm-lint
make helm-template
```

## Allowlist Format

The allowlist source should contain one IPv4 address or IPv4 CIDR per line:

```text
192.0.2.10
198.51.100.0/24
203.0.113.42 # comments are allowed
```

Blank lines and comments are ignored. IPv6 entries are not currently supported.

## Configuration

The Helm chart writes these values into a ConfigMap mounted by the daemon:

| Key | Helm value | Example | Description |
| --- | --- | --- | --- |
| `source_url` | `config.sourceUrl` | `https://example.com/team-a.txt,https://example.com/team-b.txt` | One URL, or a comma-separated list of URLs, each containing one IPv4 address or CIDR per line. |
| `protected_ports` | `config.protectedPorts` | `22,443` | Comma, space, or newline separated ports to protect. Use `*` to protect every TCP/UDP port. |
| `interface_globs` | `config.interfaceGlobs` | `eth0,cni0,veth*` | Interface names or globs where ingress filters should be attached. |
| `refresh_interval` | `config.refreshInterval` | `30s` | Config and allowlist refresh cadence. |
| `max_entries` | `config.maxEntries` | `4096` | Maximum number of allowlist prefixes loaded into the eBPF LPM trie. |

The daemon also supports equivalent environment variables:

| Config key | Environment variable |
| --- | --- |
| `source_url` | `SOURCE_URL` |
| `protected_ports` | `PROTECTED_PORTS` |
| `interface_globs` | `INTERFACE_GLOBS` |
| `refresh_interval` | `REFRESH_INTERVAL` |
| `max_entries` | `MAX_ENTRIES` |

Environment variables take precedence over mounted config files.

## Install With Helm

Build and publish an image first, then install the chart:

```bash
helm upgrade --install ebpf-firewall charts/ebpf-firewall \
  --namespace ebpf-firewall \
  --create-namespace \
  --set image.repository=your-registry/ebpf-firewall-k8s \
  --set image.tag=your-tag \
  --set-string config.sourceUrl=https://example.com/allowlist.txt \
  --set-string config.protectedPorts='22\,443' \
  --set-string config.interfaceGlobs='eth0'
```

Multiple allowlist sources are supported. Because Helm treats commas in `--set` values as separators, escape commas when setting `config.sourceUrl` from the CLI:

```bash
helm upgrade --install ebpf-firewall charts/ebpf-firewall \
  --namespace ebpf-firewall \
  --create-namespace \
  --set image.repository=your-registry/ebpf-firewall-k8s \
  --set image.tag=your-tag \
  --set-string config.sourceUrl='https://example.com/team-a.txt\,https://example.com/team-b.txt' \
  --set-string config.protectedPorts='22\,443' \
  --set-string config.interfaceGlobs='eth0'
```

Entries from all allowlist sources are merged and de-duplicated. If any source cannot be fetched or parsed, the daemon keeps retrying on the next refresh interval and leaves the previously loaded eBPF maps in place.

To protect every TCP/UDP destination port on matching interfaces:

```bash
helm upgrade --install ebpf-firewall charts/ebpf-firewall \
  --namespace ebpf-firewall \
  --create-namespace \
  --set image.repository=your-registry/ebpf-firewall-k8s \
  --set image.tag=your-tag \
  --set-string config.sourceUrl=https://example.com/allowlist.txt \
  --set-string config.protectedPorts='*' \
  --set-string config.interfaceGlobs='eth0'
```

Check rollout status:

```bash
kubectl -n ebpf-firewall rollout status daemonset/ebpf-firewall
```

View logs:

```bash
kubectl -n ebpf-firewall logs -l app.kubernetes.io/name=ebpf-firewall --all-containers
```

## Kind E2E Test

The Kind e2e test builds the daemon image and a local HTTP test image, creates a two-node Kind cluster, deploys a protected host-network server, verifies allowed traffic, updates the allowlist to deny the test client, and verifies traffic is blocked.

```bash
make e2e-kind
```

The test requires a container runtime on the host. It cannot run from restricted environments that do not expose Docker, Podman, or another compatible runtime.

Because the test loads eBPF programs inside Kind nodes, rootless Podman is usually not sufficient. Use rootful Docker or rootful Podman so the Kind node container can pass BPF privileges through to the privileged firewall DaemonSet. If firewall pod logs contain `map create: operation not permitted`, the outer Kind node container does not have the required host permission to create eBPF maps.

For local runs, Kind is invoked through your interactive `$SHELL` so aliases like `kind='systemd-run ... kind'` are respected. In CI, the script uses the normal `kind` binary. You can override either behavior:

```bash
RESPECT_KIND_ALIAS=true make e2e-kind
RESPECT_KIND_ALIAS=false make e2e-kind
```

To keep the cluster around for debugging:

```bash
KEEP_KIND_CLUSTER=true make e2e-kind
```

## Troubleshooting

If the daemon does not start, check whether the node supports eBPF and whether the pod has the required privileged security context and capabilities.

If traffic is not being filtered, confirm that `interface_globs` matches the host interface that receives ingress traffic. The daemon logs each interface it attaches to.

If allowlist updates are not reflected, confirm that `source_url` is reachable from the daemon pod and that the allowlist contents contain valid IPv4 addresses or CIDRs.

If a Kind e2e rollout times out, rerun with `KEEP_KIND_CLUSTER=true` and inspect the e2e namespace:

```bash
kubectl -n e2e get pods -o wide
kubectl -n e2e describe pods
kubectl -n e2e get events --sort-by=.lastTimestamp
```

## CI Releases

Pushes to `main` run the GitHub Actions release workflow in `.github/workflows/release.yml`.

The workflow:

- Runs `go test ./...`.
- Runs `helm lint`.
- Runs the Kind e2e test with `make e2e-kind`.
- Builds and pushes the container image to GHCR as `ghcr.io/<owner>/<repo>:sha-<short-sha>` and `latest`.
- Bumps the chart version inside the CI workspace from the checked-in major/minor version to `<major>.<minor>.<github-run-number>`.
- Sets the chart `appVersion` to the short commit SHA.
- Packages the Helm chart.
- Creates a GitHub Release named `ebpf-firewall <version>` with the chart archive attached.

The version bump is applied to the packaged release artifact during CI; it is not committed back to the repository.

The CI e2e job configures Docker with an unlimited `memlock` ulimit before creating the Kind cluster. This is required because eBPF map creation can fail inside Kind when the node container inherits a low locked-memory limit.

## License

This repository does not currently include a license file.
