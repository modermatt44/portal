package detect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/modermatt44/portal/internal/target"
)

// Default timeouts used when Options leaves them at zero.
const (
	DefaultTimeout       = 10 * time.Second
	DefaultBannerTimeout = 1 * time.Second
	DefaultTLSTimeout    = 2 * time.Second
	DefaultProbeTimeout  = 2 * time.Second
)

const (
	// bannerQuiet is how long to keep reading after the first bytes of a
	// banner arrive, to collect multi-line greetings.
	bannerQuiet = 150 * time.Millisecond
	// maxBanner caps how much of a greeting is read.
	maxBanner = 4096
	// maxParallelProbes limits concurrent active probe connections.
	maxParallelProbes = 4
)

// Options tunes detection. Zero values select the defaults.
type Options struct {
	// Timeout bounds the whole detection, including connecting.
	Timeout time.Duration
	// BannerTimeout is how long to wait for a server greeting.
	BannerTimeout time.Duration
	// TLSTimeout bounds the TLS handshake attempt.
	TLSTimeout time.Duration
	// ProbeTimeout bounds each active probe and banner confirmation.
	ProbeTimeout time.Duration
	// Logf, if set, receives a line for every step, for verbose output. It
	// may be called from several goroutines, but never concurrently.
	Logf func(format string, args ...any)
	// Probers replaces the registered probers. Tests use it to isolate a
	// single protocol.
	Probers []Prober
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.BannerTimeout <= 0 {
		o.BannerTimeout = DefaultBannerTimeout
	}
	if o.TLSTimeout <= 0 {
		o.TLSTimeout = DefaultTLSTimeout
	}
	if o.ProbeTimeout <= 0 {
		o.ProbeTimeout = DefaultProbeTimeout
	}
	if o.Probers == nil {
		o.Probers = Probers()
	}
	return o
}

// Report is the outcome of Detect.
type Report struct {
	// Target is the probed endpoint.
	Target target.Target
	// Banner is the first greeting the server sent, if any. When the port
	// speaks TLS, it is the greeting sent inside the tunnel.
	Banner []byte
	// TLS is set when the port speaks TLS from the first byte.
	TLS *TLSInfo
	// Candidates are the possible services, most likely first. It is empty
	// when nothing was identified.
	Candidates []Result
	// Elapsed is how long detection took.
	Elapsed time.Duration
}

// Best returns the candidate to use without asking the user: the top
// candidate if it is at least Likely and no other candidate is as strong.
func (r *Report) Best() (Result, bool) {
	if len(r.Candidates) == 0 {
		return Result{}, false
	}
	top := r.Candidates[0]
	if top.Confidence < Likely {
		return Result{}, false
	}
	if len(r.Candidates) > 1 && r.Candidates[1].Confidence == top.Confidence {
		return Result{}, false
	}
	return top, true
}

// ConnError means the target could not be reached at all.
type ConnError struct {
	Target target.Target
	Err    error
}

func (e *ConnError) Error() string { return fmt.Sprintf("cannot connect to %s: %v", e.Target, e.Err) }

func (e *ConnError) Unwrap() error { return e.Err }

// dialFunc opens a connection to the target, plain or through TLS.
type dialFunc func(ctx context.Context) (net.Conn, error)

type detector struct {
	t     target.Target
	opts  Options
	logMu sync.Mutex
}

// Detect identifies the service listening on t. It returns a *ConnError if
// the first connection fails; every later failure only narrows the
// candidates.
func Detect(ctx context.Context, t target.Target, opts Options) (*Report, error) {
	start := time.Now()
	opts = opts.withDefaults()
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	d := &detector{t: t, opts: opts}
	rep := &Report{Target: t}

	conn, err := d.dialTCP(ctx)
	if err != nil {
		return nil, &ConnError{Target: t, Err: err}
	}
	d.logf("connected to %s", t)

	results, banner := d.greet(ctx, d.dialTCP, conn, "tcp")
	rep.Banner = banner
	switch {
	case len(results) > 0:
		// The greeting identified the service.
	case len(banner) > 0:
		results = d.activePhase(ctx, d.dialTCP, "tcp")
	default:
		var ok bool
		if results, ok = d.tlsPhase(ctx, rep); !ok {
			results = d.activePhase(ctx, d.dialTCP, "tcp")
		}
	}

	results = merge(results)
	hint, hasHint := portHints[t.Port]
	if len(results) == 0 && hasHint {
		r := Result{
			Service:    hint.service,
			Confidence: PortHint,
			Evidence:   fmt.Sprintf("port %d is usually %s (not verified)", t.Port, hint.service.DisplayName()),
		}
		if rep.TLS != nil {
			r.TLS = rep.TLS
			if r.Service == HTTP {
				r.Service = HTTPS
			}
		}
		d.logf("no probe matched; using port hint: %s", r.Service)
		results = append(results, r)
	}
	sortResults(results, hint.service)
	rep.Candidates = results
	rep.Elapsed = time.Since(start)
	return rep, nil
}

func (d *detector) logf(format string, args ...any) {
	if d.opts.Logf == nil {
		return
	}
	d.logMu.Lock()
	defer d.logMu.Unlock()
	d.opts.Logf(format, args...)
}

func (d *detector) dialTCP(ctx context.Context) (net.Conn, error) {
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", d.t.Addr())
}

// greet reads the server's greeting on conn and runs the banner phase. It
// takes ownership of conn. It returns the banner matches and the banner.
func (d *detector) greet(ctx context.Context, dial dialFunc, conn net.Conn, layer string) ([]Result, []byte) {
	banner := readBanner(ctx, conn, d.opts.BannerTimeout)
	if len(banner) == 0 {
		conn.Close()
		d.logf("%s: no banner within %v", layer, d.opts.BannerTimeout)
		return nil, nil
	}
	d.logf("%s: banner %s", layer, quoteBanner(banner))
	results := d.bannerPhase(ctx, dial, conn, banner)
	if len(results) == 0 {
		d.logf("%s: banner not recognized", layer)
	}
	return results, banner
}

// bannerPhase matches banner against every BannerProber and lets matching
// Confirmers talk to the server. The first Confirmer reuses conn; later
// ones get a fresh connection. It takes ownership of conn.
func (d *detector) bannerPhase(ctx context.Context, dial dialFunc, conn net.Conn, banner []byte) []Result {
	var (
		results []Result
		owners  []BannerProber
	)
	for _, p := range d.opts.Probers {
		bp, ok := p.(BannerProber)
		if !ok {
			continue
		}
		if r := bp.MatchBanner(banner); r != nil {
			if r.Service == "" {
				r.Service = bp.Service()
			}
			d.logf("banner %s: %s (%s)", bp.Name(), r.Confidence, r.Evidence)
			results = append(results, *r)
			owners = append(owners, bp)
		}
	}

	fresh := conn
	defer func() {
		if fresh != nil {
			fresh.Close()
		}
	}()
	for i, bp := range owners {
		c, ok := bp.(Confirmer)
		if !ok {
			continue
		}
		cconn, cbanner := fresh, banner
		fresh = nil
		if cconn == nil {
			var err error
			if cconn, err = dial(ctx); err != nil {
				d.logf("confirm %s: %v", bp.Name(), err)
				continue
			}
			cbanner = readBanner(ctx, cconn, d.opts.BannerTimeout)
		}
		r, err := d.confirm(ctx, c, cconn, cbanner)
		cconn.Close()
		switch {
		case err != nil:
			d.logf("confirm %s: %v", bp.Name(), err)
		case r != nil:
			if r.Service == "" {
				r.Service = bp.Service()
			}
			d.logf("confirm %s: %s (%s)", bp.Name(), r.Confidence, r.Evidence)
			results[i] = *r
		default:
			d.logf("confirm %s: not confirmed", bp.Name())
		}
	}
	return results
}

func (d *detector) confirm(ctx context.Context, c Confirmer, conn net.Conn, banner []byte) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, d.opts.ProbeTimeout)
	defer cancel()
	setDeadline(ctx, conn)
	return c.Confirm(ctx, conn, d.t, banner)
}

// activePhase runs every ActiveProber concurrently, each on its own
// connection, and returns the matches in prober order.
func (d *detector) activePhase(ctx context.Context, dial dialFunc, layer string) []Result {
	var probers []ActiveProber
	for _, p := range d.opts.Probers {
		if ap, ok := p.(ActiveProber); ok {
			probers = append(probers, ap)
		}
	}
	found := make([]*Result, len(probers))
	sem := make(chan struct{}, maxParallelProbes)
	var wg sync.WaitGroup
	for i, p := range probers {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			found[i] = d.probe(ctx, dial, p, layer)
		})
	}
	wg.Wait()

	var results []Result
	for _, r := range found {
		if r != nil {
			results = append(results, *r)
		}
	}
	return results
}

func (d *detector) probe(ctx context.Context, dial dialFunc, p ActiveProber, layer string) *Result {
	ctx, cancel := context.WithTimeout(ctx, d.opts.ProbeTimeout)
	defer cancel()
	conn, err := dial(ctx)
	if err != nil {
		d.logf("%s probe %s: connect: %v", layer, p.Name(), err)
		return nil
	}
	defer conn.Close()
	setDeadline(ctx, conn)
	r, err := p.Probe(ctx, conn, d.t)
	switch {
	case err != nil:
		d.logf("%s probe %s: no match (%v)", layer, p.Name(), describeErr(err))
		return nil
	case r == nil:
		d.logf("%s probe %s: no match", layer, p.Name())
		return nil
	}
	if r.Service == "" {
		r.Service = p.Service()
	}
	d.logf("%s probe %s: %s (%s)", layer, p.Name(), r.Confidence, r.Evidence)
	return r
}

// readBanner waits up to wait for the server to send something, then keeps
// reading briefly to collect multi-line greetings. Read errors end the
// banner; they are not reported.
func readBanner(ctx context.Context, conn net.Conn, wait time.Duration) []byte {
	defer conn.SetReadDeadline(time.Time{})
	conn.SetReadDeadline(earliest(ctx, time.Now().Add(wait)))
	var banner []byte
	buf := make([]byte, 1024)
	for len(banner) < maxBanner {
		n, err := conn.Read(buf)
		banner = append(banner, buf[:n]...)
		if err != nil {
			break
		}
		conn.SetReadDeadline(earliest(ctx, time.Now().Add(bannerQuiet)))
	}
	return banner
}

// setDeadline applies ctx's deadline to conn.
func setDeadline(ctx context.Context, conn net.Conn) {
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
}

// earliest returns t or ctx's deadline, whichever comes first.
func earliest(ctx context.Context, t time.Time) time.Time {
	if dl, ok := ctx.Deadline(); ok && dl.Before(t) {
		return dl
	}
	return t
}

// describeErr shortens common network errors for verbose output.
func describeErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return err.Error()
}

// merge removes duplicate services, keeping the strongest result for each.
func merge(results []Result) []Result {
	var out []Result
	index := map[Service]int{}
	for _, r := range results {
		i, seen := index[r.Service]
		switch {
		case !seen:
			index[r.Service] = len(out)
			out = append(out, r)
		case r.Confidence > out[i].Confidence:
			out[i] = r
		}
	}
	return out
}

// sortResults orders results by confidence. Among equally confident
// results, the one matching the port's conventional service comes first:
// the port is a tie-breaker, never evidence.
func sortResults(results []Result, hinted Service) {
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		return a.Service == hinted && b.Service != hinted
	})
}
