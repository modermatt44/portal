package detect

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/modermatt44/portal/internal/target"
)

// Prober identifies one protocol. Every Prober also implements
// BannerProber, ActiveProber, or both.
type Prober interface {
	// Name is a short, unique identifier used in verbose output, e.g. "ssh".
	Name() string
	// Service is the protocol this prober identifies.
	Service() Service
}

// BannerProber recognizes protocols whose servers speak first.
type BannerProber interface {
	Prober
	// MatchBanner inspects the greeting the server sent on connect and
	// returns nil if it does not belong to this protocol. It must not do
	// any I/O; implement Confirmer to talk to the server.
	MatchBanner(banner []byte) *Result
}

// Confirmer is implemented by a BannerProber that can verify or enrich a
// banner match by talking to the server, e.g. SMTP sending EHLO to learn
// whether STARTTLS is offered. It is only called for matches that are not
// already Confirmed.
type Confirmer interface {
	// Confirm is called with a connection whose greeting (banner) has
	// already been read. It returns the improved result, or nil to keep the
	// result of MatchBanner.
	Confirm(ctx context.Context, conn net.Conn, t target.Target, banner []byte) (*Result, error)
}

// ActiveProber recognizes protocols whose servers wait for the client to
// speak first.
type ActiveProber interface {
	Prober
	// Probe sends a request on a fresh connection and inspects the reply.
	// It returns nil, nil if the reply does not belong to this protocol.
	// The connection's deadline is already set.
	Probe(ctx context.Context, conn net.Conn, t target.Target) (*Result, error)
}

var (
	registryMu sync.Mutex
	registry   = map[string]Prober{}
)

// Register makes p available to Detect. It is meant to be called from an
// init function. It panics if p implements neither BannerProber nor
// ActiveProber, or if a prober with the same name is already registered.
func Register(p Prober) {
	_, isBanner := p.(BannerProber)
	_, isActive := p.(ActiveProber)
	if !isBanner && !isActive {
		panic(fmt.Sprintf("detect: prober %q implements neither BannerProber nor ActiveProber", p.Name()))
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[p.Name()]; dup {
		panic(fmt.Sprintf("detect: prober %q registered twice", p.Name()))
	}
	registry[p.Name()] = p
}

// Probers returns the registered probers sorted by name.
func Probers() []Prober {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]Prober, 0, len(registry))
	for _, p := range registry {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
