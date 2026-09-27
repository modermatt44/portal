package cli

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/modermatt44/portal/internal/clients"
	"github.com/modermatt44/portal/internal/detect"
	"github.com/modermatt44/portal/internal/rawsession"
	"github.com/modermatt44/portal/internal/target"
)

// handoff resolves the client for the chosen service and gives it the
// terminal. how says how the service was determined, e.g. "detected".
func (a *app) handoff(ctx context.Context, t target.Target, choice detect.Result, how string, extra []string) error {
	cmd, err := a.resolver.Resolve(a.request(t, choice, extra))
	var missing *clients.MissingError
	switch {
	case errors.As(err, &missing):
		return a.handleMissing(ctx, t, choice, how, cmd, missing)
	case err != nil:
		return &Error{Code: ExitNoClient, Err: err, Hint: "use the raw session with --service raw"}
	}
	if a.opts.dryRun {
		fmt.Fprintln(a.streams.Out, cmd.String())
		return nil
	}
	a.announce(t, choice, how, "→ "+action(cmd))
	return a.launch(ctx, t, cmd)
}

// request builds the client request for choice, applying the configured
// preferred client.
func (a *app) request(t target.Target, choice detect.Result, extra []string) clients.Request {
	return clients.Request{
		Target:    t,
		Service:   choice.Service,
		TLS:       choice.ImplicitTLS(),
		StartTLS:  choice.StartTLS,
		Extra:     extra,
		Preferred: a.cfg.Client(t, choice.Service),
	}
}

// action describes what launching cmd does, e.g. "launching psql".
func action(cmd clients.Command) string {
	if cmd.Builtin {
		return "opening a " + rawLabel(cmd.TLS)
	}
	return "launching " + cmd.Name
}

// announce prints the one line shown before handing off, e.g.
// "✓ PostgreSQL 16.2 detected on db.local:5432 → launching psql".
func (a *app) announce(t target.Target, choice detect.Result, how, suffix string) {
	if suffix != "" {
		suffix = " " + suffix
	}
	switch {
	case choice.Service == detect.Unknown && how == "detected":
		a.status("?", fmt.Sprintf("No known service detected on %s%s", t, suffix))
	case choice.Service == detect.Unknown:
		a.status("✓", fmt.Sprintf("Raw session to %s (%s)%s", t, how, suffix))
	case how == "detected":
		a.status("✓", fmt.Sprintf("%s detected on %s%s", choice.Label(), t, suffix))
	default:
		a.status("✓", fmt.Sprintf("%s on %s (%s)%s", choice.Label(), t, how, suffix))
	}
	if tls := choice.TLS; tls != nil && tls.VerifyError != "" {
		note := "certificate is not trusted: " + tls.VerifyError
		if choice.Service == detect.HTTPS {
			note += " (to let curl connect anyway, add: -- -k)"
		}
		fmt.Fprintf(a.streams.Err, "  %s %s\n", a.err.Yellow("!"), note)
	}
}

// handleMissing explains that the client is not installed and offers the
// raw session instead.
func (a *app) handleMissing(ctx context.Context, t target.Target, choice detect.Result, how string, cmd clients.Command, missing *clients.MissingError) error {
	noClient := &Error{
		Code: ExitNoClient,
		Err:  missing,
		Hint: fmt.Sprintf("install it: %s\n    or use portal's raw session: portal --service raw %s", missing.Hint, t),
	}
	if a.opts.dryRun {
		fmt.Fprintln(a.streams.Out, cmd.String())
		return noClient
	}
	a.announce(t, choice, how, "")
	if !a.streams.InTTY {
		return noClient
	}
	a.status("✗", missing.Error())
	fmt.Fprintf(a.streams.Err, "  %s install it: %s\n", a.err.Dim("→"), missing.Hint)
	raw := clients.Command{Builtin: true, TLS: choice.ImplicitTLS(), CRLF: choice.Service != detect.Unknown}
	if !a.confirm(fmt.Sprintf("Open a %s instead?", rawLabel(raw.TLS)), true) {
		return exitStatus(ExitNoClient)
	}
	return a.launch(ctx, t, raw)
}

// launch runs cmd. On Unix, a successful launch of an external program
// never returns.
func (a *app) launch(ctx context.Context, t target.Target, cmd clients.Command) error {
	if cmd.Builtin {
		return a.rawSession(ctx, t, cmd.TLS, cmd.CRLF)
	}
	err := clients.Exec(cmd)
	var ee *clients.ExitError
	switch {
	case errors.As(err, &ee):
		return exitStatus(ee.Code)
	case err != nil:
		return &Error{Code: ExitNoClient, Err: fmt.Errorf("cannot start %s: %w", cmd.Name, err), Hint: fmt.Sprintf("check that %s works on its own, e.g. %s --version", cmd.Name, cmd.Name)}
	}
	return nil
}

// status prints a status line to stderr with a colored mark.
func (a *app) status(mark, msg string) {
	switch mark {
	case "✓":
		mark = a.err.Green(mark)
	case "?":
		mark = a.err.Yellow(mark)
	case "✗":
		mark = a.err.Red(mark)
	}
	fmt.Fprintf(a.streams.Err, "%s %s\n", mark, msg)
}

func (a *app) rawSession(ctx context.Context, t target.Target, useTLS, crlf bool) error {
	kind := "TCP"
	if useTLS {
		kind = "TLS"
	}
	fmt.Fprintf(a.streams.Err, "%s\n", a.err.Dim(fmt.Sprintf("Connected to %s (raw %s). Type to send; Ctrl+C to quit.", t, kind)))
	serverName := ""
	if !t.IsIP() {
		serverName = t.Host
	}
	err := rawsession.Run(ctx, t.Addr(), rawsession.Options{
		TLS:        useTLS,
		ServerName: serverName,
		CRLF:       crlf,
		Stdin:      a.streams.In,
		Stdout:     a.streams.Out,
		Stderr:     a.streams.Err,
	})
	if err != nil {
		return connectionError(t, err)
	}
	return nil
}

// connectionError turns a dial error into an Error with a hint that fits
// the failure.
func connectionError(t target.Target, err error) *Error {
	var dnsErr *net.DNSError
	var netErr net.Error
	hint := "check the host and port, and that no firewall is blocking the connection"
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		hint = fmt.Sprintf("check the spelling of %q, or use an IP address", t.Host)
	case errors.As(err, &dnsErr):
		hint = fmt.Sprintf("could not resolve %q; check the name and your network or DNS settings", t.Host)
	case errors.As(err, &netErr) && netErr.Timeout(), errors.Is(err, context.DeadlineExceeded):
		hint = "the host may be down or a firewall may be dropping packets; try a longer --timeout, e.g. --timeout 30s"
	case isConnRefused(err):
		hint = fmt.Sprintf("nothing is listening on port %d; check that the service is running and the port is right", t.Port)
		return &Error{Code: ExitConnection, Err: fmt.Errorf("cannot connect to %s: connection refused", t), Hint: hint}
	}
	return &Error{Code: ExitConnection, Err: fmt.Errorf("cannot connect to %s: %w", t, unwrapOp(err)), Hint: hint}
}

// unwrapOp strips the "dial tcp 1.2.3.4:5:" prefix of *net.OpError, since
// portal already names the target.
func unwrapOp(err error) error {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err
	}
	return err
}
