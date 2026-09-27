# Contributing to portal

Thanks for helping! Most contributions add a protocol, so this guide centers on that. Bug fixes and better client mappings are just as welcome.

## Ground rules

- Standard library only. Cobra is the one allowed dependency. Don't add others.
- Code must be `gofmt`-formatted and pass `go vet` and `go test ./...` on Linux, macOS and Windows. `make lint test` checks this.
- Tests must not use the external network. Use the fake servers in `internal/fakeserver`.
- Exported identifiers need doc comments. Error messages say what went wrong and what to do next.
- Keep commits small, with descriptive messages in the imperative mood ("Add memcached probe").

## Adding a new probe

A protocol is one file in `internal/detect`, plus a test file, plus a line in the client registry.

### 1. Pick the probe kind

| The server… | Implement | Example |
|---|---|---|
| speaks first (sends a greeting on connect) | `BannerProber`, plus `Confirmer` if the greeting alone is ambiguous | `ssh.go`, `smtp.go`, `mysql.go` |
| waits for the client | `ActiveProber` | `redis.go`, `http.go`, `postgres.go` |

A prober can implement both.

### 2. Add the service

In `internal/detect/detect.go`, add a `Service` constant and its display name in `displayNames`:

```go
Memcached Service = "memcached"
...
Memcached: "Memcached",
```

If the protocol has a well-known port, add it to `portHints` in `porthints.go`. It only breaks ties and serves as an unverified fallback.

### 3. Write the probe

Create `internal/detect/memcached.go`:

```go
package detect

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"

	"github.com/modermatt44/portal/internal/target"
)

func init() { Register(memcachedProber{}) }

// memcachedProber sends "version" and expects "VERSION x.y.z".
type memcachedProber struct{}

func (memcachedProber) Name() string     { return "memcached" }
func (memcachedProber) Service() Service { return Memcached }

// Probe sends the text-protocol version command.
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
		return nil, nil // some other protocol
	}
	return &Result{
		Version:    v,
		Confidence: Confirmed,
		Evidence:   "answered version with " + quoteBanner([]byte(line)),
	}, nil
}
```

The contract:

- Return `nil, nil` when the reply isn't your protocol. Return an error only for I/O failures; it shows up in `--verbose` output.
- The engine sets the connection deadline, closes the connection afterwards, and fills in `Result.Service` if you leave it empty.
- Choose the confidence honestly:
  - `Confirmed`: the server answered a protocol exchange correctly.
  - `Likely`: a distinctive signature matched but wasn't exercised.
  - `Possible`: the evidence fits several protocols, like a bare `220` greeting.
- `MatchBanner` must not do I/O. If it needs to talk to the server, implement `Confirmer`. It runs only for matches that aren't already `Confirmed`, and gets a connection whose greeting was already read.
- Be a polite client. Send the smallest request that identifies the protocol, never send credentials, and say goodbye (`QUIT`, `LOGOUT`) if the protocol has a way to.
- Put protocol facts in `Details` (e.g. `r.setDetail("auth", "required")`) and server software in `Product` and `Version`.
- Probes inside TLS work automatically: the engine runs every probe through the tunnel when the port speaks TLS.

Update the list of what portal sends in the README's "Responsible use" section.

### 4. Test it with a fake server

Create `internal/detect/memcached_test.go`. `fakeserver.Lines` fits line-based protocols; for binary protocols, pass your own `func(net.Conn)` to `fakeserver.Start`. Use `fakeserver.StartTLS` for the TLS variant.

```go
func TestDetectMemcached(t *testing.T) {
	t.Parallel()
	s := fakeserver.Start(t, fakeserver.Lines("", func(line string) (string, bool) {
		if line == "version" {
			return "VERSION 1.6.21\r\n", false
		}
		return "ERROR\r\n", false
	}))
	best := wantBest(t, detectFake(t, s), Memcached, Confirmed)
	if best.Version != "1.6.21" {
		t.Errorf("version = %q", best.Version)
	}
}
```

`detectFake` runs the full engine with every registered probe. That checks both that your probe recognizes its server and that the other probes don't misidentify it. Make the fake behave like the real server when it gets requests meant for other protocols; usually that means hanging up.

For banner probes, also add a table-driven test of `MatchBanner` with real greetings from a few server implementations, plus some that must not match.

### 5. Map it to a client

In `internal/clients/registry.go`, define the client with its arguments and install hints, then add it to `registry` in order of preference:

```go
memcachedClient = Client{
	Program: "telnet",
	Args:    func(r Request) []string { return []string{r.Target.Host, port(r)} },
	Install: map[string]string{"darwin": "brew install telnet", "": "sudo apt install telnet"},
}
...
detect.Memcached: {memcachedClient, textSession},
```

Text protocols can fall back to `textSession`, portal's built-in session with CRLF line endings. Add a row to `TestResolveDefaults` in `internal/clients/clients_test.go`.

### 6. Document it

Add a row to the "Supported protocols" table in `README.md`.

## Running checks

```sh
make lint test          # or: gofmt -l . && go vet ./... && go test ./...
make cross              # make sure every platform still builds
go run ./cmd/portal -v -d localhost:11211   # try it against a real server
```
