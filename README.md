# portal

**Point `portal` at any `host:port` and it figures out what's running there and opens the right client, so you don't have to remember which tool speaks which protocol.**

```console
$ portal db.local:5432
✓ PostgreSQL detected on db.local:5432 → launching psql
psql (16.2)
Type "help" for help.

app=>
```

```console
$ portal server:22              # ✓ SSH (OpenSSH 9.6p1) detected on server:22 → launching ssh
$ portal example.com:443        # ✓ HTTPS (cloudflare) detected on example.com:443 → launching curl
$ portal 10.0.0.5:6379          # ✓ Redis 7.2.4 detected on 10.0.0.5:6379 → launching redis-cli
$ portal mail.local:25          # ✓ SMTP (Postfix) detected on mail.local:25 → launching openssl
$ portal 10.0.0.9:7000          # ? No known service detected on 10.0.0.9:7000 → opening a raw TCP session
```

It is a single static binary for Linux, macOS and Windows, with no runtime dependencies and no nmap.

## Contents

- [Install](#install)
- [Usage](#usage)
- [Flags](#flags)
- [Supported protocols](#supported-protocols)
- [Configuration](#configuration)
- [How detection works](#how-detection-works)
- [Adding a protocol](#adding-a-protocol)
- [Development](#development)
- [Responsible use](#responsible-use)

## Install

With Go 1.27 or newer:

```sh
go install github.com/modermatt44/portal/cmd/portal@latest
```

This puts `portal` in `$(go env GOPATH)/bin` (usually `~/go/bin`). Make sure that directory is on your `PATH`.

From source:

```sh
git clone https://github.com/modermatt44/portal.git
cd portal
make build            # or: go build -o bin/portal ./cmd/portal
./bin/portal --version
```

Release binaries for every platform can be built with `make cross`. Without `make`, run this for each platform:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o portal-linux-arm64 ./cmd/portal
```

portal launches the usual clients (`psql`, `ssh`, `redis-cli`, `curl`, …). It doesn't bundle them. If one is missing, portal says how to install it and offers its built-in raw session instead.

## Usage

```
portal <host:port | host port> [flags] [-- client args...]
```

The target can be written several ways:

| Form | Example |
|---|---|
| `host:port` | `portal db.local:5432` |
| `host port` | `portal db.local 5432` |
| IPv6 in brackets | `portal [::1]:6379`, or `portal ::1 6379` |
| URL (port from the scheme if omitted) | `portal https://example.com`, `portal postgres://db:6543/app` |

Before handing off, portal prints one line that says what it found and what it's about to run:

```
✓ PostgreSQL detected on db.local:5432 → launching psql
```

Anything after `--` is passed to the client, after the connection arguments:

```console
$ portal --dry-run db.local:5432 -- -U admin mydb
psql -h db.local -p 5432 -U admin mydb
```

**Only detect.** Use `-d` for a readable report, or `--json` for scripts:

```console
$ portal -d example.com:443
✓ HTTPS (cloudflare) on example.com:443 (confirmed)
    evidence  answered GET / with "HTTP/1.1 200 OK"
    status    200 OK
    tls       TLS 1.3 · TLS_AES_128_GCM_SHA256 · ALPN h2
    subject   CN=example.com
    issuer    CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US
    names     example.com, *.example.com
    expires   2026-12-25 (89 days left)
    trusted   yes
    client    curl -v https://example.com

$ portal --json 10.0.0.5:6379 | jq -r .service
redis
```

**Ambiguous results.** If the evidence fits more than one service, portal asks:

```
? Several services could be on files.local:2121:
  1) FTP              possible  bare 220 greeting, used by SMTP and FTP
  2) SMTP             possible  bare 220 greeting, used by SMTP and FTP
  3) raw TCP session
Choose 1-3 [1], or q to quit:
```

Without a terminal (in scripts, for example), portal exits with code 2 and suggests `--service`.

**Missing client.** portal says what's missing and how to get it:

```
✓ Redis 7.2.4 detected on 10.0.0.5:6379
✗ redis-cli is not installed (also looked for valkey-cli)
  → install it: brew install redis
Open a raw TCP session instead? [Y/n]
```

**Verbose.** `-v` shows every step with timings, on stderr:

```console
$ portal -v -d example.com:443
   29ms connected to example.com:443
 1029ms tcp: no banner within 1s
 1067ms tls: TLS 1.3, TLS_AES_128_GCM_SHA256, ALPN "h2", subject "CN=example.com", ...
 1093ms tls probe http: confirmed (answered GET / with "HTTP/1.1 200 OK")
✓ HTTPS (cloudflare) on example.com:443 (confirmed)
...
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. Once a client has started, portal exits with the client's own exit code. |
| 1 | Connection error: unknown host, port closed, or timeout |
| 2 | Usage error, or no choice was made at a prompt |
| 3 | No client program is available for the service |

Every error says what went wrong and what to try next:

```
✗ cannot connect to db.local:5433: connection refused
  → nothing is listening on port 5433; check that the service is running and the port is right
```

Output is colored only on a terminal, and never when `NO_COLOR` is set.

## Flags

| Flag | Description |
|---|---|
| `-d`, `--detect-only` | Print what was detected, including the client command, and don't connect. |
| `--json` | Print the detection result as JSON. Implies `--detect-only`. |
| `-n`, `--dry-run` | Print the client command instead of running it. |
| `-t`, `--timeout <duration>` | Overall time limit for detection (default `10s`), e.g. `3s`, `500ms`. |
| `-v`, `--verbose` | Show which probes ran and what they saw, on stderr. |
| `-s`, `--service <name>` | Skip detection and treat the port as this service. `raw` and `tls` open the built-in session. Aliases such as `postgres`, `mariadb` and `mongo` work. |
| `--config <file>` | Read this config file instead of the default. |
| `--version` | Print the version. |
| `-h`, `--help` | Show help with examples. |

## Supported protocols

| Service | How it is detected | Client (first installed wins) |
|---|---|---|
| SSH | Banner `SSH-2.0-…` (RFC 4253) | `ssh -p PORT HOST` |
| SMTP | `220` greeting, confirmed with `EHLO`; if STARTTLS is offered, the upgrade is done and the certificate reported | `openssl s_client -starttls smtp …` when STARTTLS is offered, otherwise the built-in session |
| FTP | `220` greeting, confirmed with `FEAT` or `SYST` | `lftp -p PORT HOST`, `ftp HOST PORT` |
| IMAP | `* OK` greeting, confirmed with `CAPABILITY` | built-in session (CRLF) |
| POP3 | `+OK` greeting, confirmed with `CAPA` | built-in session (CRLF) |
| MySQL / MariaDB | Server handshake packet (version, auth plugin) or error packet | `mysql -h HOST -P PORT --protocol=TCP`, `mariadb`, `mycli` |
| HTTP | `GET /` answered with an `HTTP/1.x` status line | `curl -v http://HOST:PORT` |
| HTTPS | TLS handshake, then HTTP inside the tunnel, or an `h2`/`http/1.1` ALPN | `curl -v https://HOST` |
| PostgreSQL | `SSLRequest` answered with `S`/`N`, then a startup message that reveals the auth method | `psql -h HOST -p PORT`, `pgcli` |
| Redis | RESP `PING` answered with `+PONG`, `-NOAUTH` or `-DENIED`; `INFO server` for the version (Valkey is recognized too) | `redis-cli -h HOST -p PORT [--tls]`, `valkey-cli` |
| MongoDB | `isMaster` over OP_MSG, `buildInfo` for the version | `mongosh --host HOST --port PORT [--tls]`, `mongo` |
| Other TLS | TLS handshake succeeds, nothing recognized inside | built-in TLS session |
| Anything else | – | built-in raw TCP session (like `nc`) |

Services that speak TLS from the first byte (IMAPS on 993, POP3S on 995, SMTPS on 465, Redis or MongoDB with TLS) are detected inside the tunnel. The client is then started in TLS mode, or the built-in session wraps the connection in TLS.

The built-in session is an interactive relay between your terminal and the socket. For line-based text protocols it sends CRLF line endings.

## Configuration

portal works without a config file. To customize it, create one at:

| OS | Location |
|---|---|
| Linux, macOS, BSD | `$XDG_CONFIG_HOME/portal/config.toml`, or `~/.config/portal/config.toml` |
| Windows | `%AppData%\portal\config.toml` |
| Any | the path in `$PORTAL_CONFIG`, or `--config <file>` |

The format is a small subset of [TOML](https://toml.io): `[tables]`, `key = "string"` and `# comments`.

```toml
# Preferred client per service. A bare program name that portal knows gets
# its usual connection arguments. Anything else is a template with
# {host}, {port} and {addr} placeholders.
[clients]
postgresql = "pgcli"
mysql      = "mycli"
ssh        = "mosh --ssh='ssh -p {port}' {host}"
redis      = "redis-cli -h {host} -p {port} -n 2"

# Detection timeouts. The --timeout flag overrides "timeout".
[detect]
timeout        = "10s"   # overall limit
banner_timeout = "1s"    # how long to wait for a greeting
tls_timeout    = "2s"    # TLS handshake attempt
probe_timeout  = "2s"    # each active probe

# Per-endpoint overrides. "service" skips detection; "client" overrides
# [clients] for this endpoint only.
[hosts."cache.local:6380"]
service = "redis"
client  = "redis-cli -h {host} -p {port} --tls"

# "*" matches any host on that port.
[hosts."*:2222"]
service = "ssh"

# Always use the raw session for this device.
[hosts."10.0.0.50:9100"]
service = "raw"
```

Unknown tables, keys and services are reported with the line number, so typos don't go unnoticed.

Precedence: `--service`, then a `[hosts]` override, then detection. For the client, a `[hosts]` client wins over `[clients]`, which wins over the built-in defaults.

## How detection works

Each step has its own short timeout, and all of them fit within `--timeout`:

1. **Banner.** portal connects and waits about a second for the server to speak first. SSH, SMTP, FTP, IMAP, POP3 and MySQL do. The greeting is matched against every banner probe. If the match is weak (a bare `220` fits SMTP and FTP alike), the probe confirms it by speaking the protocol (`EHLO`, `FEAT`, …) on a fresh connection.
2. **TLS.** If the server stays silent, portal tries a TLS handshake. On success it reports the TLS version, cipher, ALPN, certificate subject, issuer, names and expiry, and whether the certificate is trusted. Then it runs detection again *inside* the tunnel.
3. **Active probes.** Probes for protocols where the client speaks first (HTTP, Redis, PostgreSQL, MongoDB) run concurrently, each on its own connection.
4. **Port number.** Only if nothing matched, the well-known port becomes an unverified hint ("port 5432 is usually PostgreSQL") that you are asked to confirm. The port also breaks ties between equally strong candidates. It is never treated as proof.

Each result has a confidence level: `confirmed` (the server spoke the protocol correctly), `likely` (a signature matched), `possible` (the evidence fits several protocols) or `port-hint`. portal proceeds on its own only when one candidate is at least `likely` and clearly ahead of the rest. Otherwise it asks.

## Adding a protocol

Every protocol is one file in `internal/detect`. A probe implements `Prober` plus either `BannerProber` (the server speaks first) or `ActiveProber` (the client speaks first), and registers itself in `init()`:

```go
func init() { Register(memcachedProber{}) }

type memcachedProber struct{}

func (memcachedProber) Name() string     { return "memcached" }
func (memcachedProber) Service() Service { return Memcached }

func (memcachedProber) Probe(ctx context.Context, conn net.Conn, t target.Target) (*Result, error) {
	if _, err := io.WriteString(conn, "version\r\n"); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil, err
	}
	v, ok := strings.CutPrefix(strings.TrimSpace(line), "VERSION ")
	if !ok {
		return nil, nil // not memcached
	}
	return &Result{Version: v, Confidence: Confirmed, Evidence: "answered version"}, nil
}
```

Then add the client in `internal/clients/registry.go` and a test with a fake server. [CONTRIBUTING.md](CONTRIBUTING.md) walks through the details.

## Development

| Task | With make | Without make |
|---|---|---|
| Build | `make build` | `go build -o bin/portal ./cmd/portal` |
| Test | `make test` | `go test ./...` |
| Lint | `make lint` | `gofmt -l .` (must print nothing), `go vet ./...`, optionally `staticcheck ./...` |
| Cross-compile | `make cross` | `GOOS=<os> GOARCH=<arch> CGO_ENABLED=0 go build ./cmd/portal` |

The tests start fake servers on `127.0.0.1` that emulate each protocol's banner or handshake, so no external network is needed.

Project layout:

```
cmd/portal/            entry point
internal/cli/          flags, help, output, prompts, hand-off
internal/detect/       detection engine and one file per protocol
internal/clients/      service → client mapping, install hints, exec
internal/config/       config file (TOML subset)
internal/rawsession/   built-in interactive TCP/TLS session
internal/target/       host:port parsing
internal/term/         terminal and color detection
internal/fakeserver/   fake servers for tests
```

## Responsible use

portal opens connections and sends protocol requests, much like a port scanner's service detection. **Only use it against hosts you own or are explicitly authorized to test.** Probing other people's systems may break their terms of service or the law.

To keep probes predictable, here is everything portal sends:

- **SMTP:** `EHLO localhost`, `STARTTLS` if offered, then `QUIT`
- **FTP:** `FEAT` or `SYST`, then `QUIT`
- **IMAP:** `CAPABILITY`, then `LOGOUT`
- **POP3:** `CAPA`, then `QUIT`
- **HTTP:** `GET /`
- **Redis:** `PING` and `INFO server`
- **MongoDB:** `isMaster` and `buildInfo`
- **PostgreSQL:** an `SSLRequest` and a startup message for user `portal`

portal never sends a password. The detection probes, plus a TLS handshake when the port is silent, run on each invocation unless you use `--service` or a `[hosts]` override.
