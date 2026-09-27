// Package cli implements portal's command-line interface: argument parsing,
// output, the interactive chooser and the hand-off to client programs.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/modermatt44/portal/internal/rawsession"
	"github.com/modermatt44/portal/internal/target"
	"github.com/modermatt44/portal/internal/term"
)

// Streams are the terminal streams the CLI reads from and writes to.
type Streams struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer

	// InTTY reports whether In is an interactive terminal, which enables
	// prompts.
	InTTY bool
	// OutColor and ErrColor enable ANSI colors on Out and Err.
	OutColor bool
	ErrColor bool
}

// DefaultStreams returns the process's standard streams with terminal and
// color detection applied.
func DefaultStreams() Streams {
	return Streams{
		In:       os.Stdin,
		Out:      os.Stdout,
		Err:      os.Stderr,
		InTTY:    term.IsTerminal(os.Stdin),
		OutColor: term.ColorEnabled(os.Stdout),
		ErrColor: term.ColorEnabled(os.Stderr),
	}
}

type options struct {
	detectOnly bool
	jsonOut    bool
	verbose    bool
	dryRun     bool
	timeout    time.Duration
}

type app struct {
	opts    options
	streams Streams
	out     term.Style // style for Out
	err     term.Style // style for Err
}

const longHelp = `portal connects to a TCP port, figures out which service is running there,
and hands your terminal over to the right client (psql, ssh, redis-cli, ...).

Detection runs in this order, each step with a short timeout:
  1. wait briefly for a banner (SSH, SMTP, FTP, IMAP, POP3, MySQL send one)
  2. try a TLS handshake and, if it works, detect again inside the tunnel
  3. send active probes (HTTP, Redis, PostgreSQL, MongoDB)
  4. fall back to the well-known port number as an unverified hint

Unknown services open a raw interactive session (like nc), over TLS if the
port speaks TLS.

Exit codes:
  0  success
  1  connection error (host unreachable, port closed, timeout)
  2  usage error, or no choice was made at a prompt
  3  no client program is available for the detected service

Only probe hosts you are authorized to test.`

const examples = `  # Detect the service and open the matching client
  portal db.local:5432            # PostgreSQL → psql -h db.local -p 5432
  portal server:22                # SSH        → ssh -p 22 server
  portal example.com:443          # HTTPS      → curl -v https://example.com

  # Host and port as separate arguments, IPv6 in brackets, or a URL
  portal server 22
  portal [::1]:6379
  portal https://example.com

  # Pass extra arguments to the client after --
  portal db.local:5432 -- -U admin mydb

  # Only detect, as text or JSON
  portal --detect-only example.com:443
  portal -d --json 10.0.0.5:6379

  # Print the client command instead of running it
  portal --dry-run db.local:5432

  # See which probes ran and what they saw, with a longer time limit
  portal -v --timeout 20s slow.example.com:8080`

// NewRootCommand builds the portal command. version is shown by --version.
func NewRootCommand(version string, streams Streams) *cobra.Command {
	a := &app{
		streams: streams,
		out:     term.Style{Enabled: streams.OutColor},
		err:     term.Style{Enabled: streams.ErrColor},
	}
	cmd := &cobra.Command{
		Use:     "portal <host:port | host port> [-- client args...]",
		Short:   "Detect the service on a TCP port and open the right client",
		Long:    longHelp,
		Example: examples,
		Version: version,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usageError(errors.New("missing target"), "try: portal db.local:5432, or see portal --help")
			}
			return nil
		},
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			targetArgs, extra := splitArgs(args, cmd.ArgsLenAtDash())
			return a.run(cmd.Context(), targetArgs, extra)
		},
	}
	cmd.SetIn(streams.In)
	cmd.SetOut(streams.Out)
	cmd.SetErr(streams.Err)

	f := cmd.Flags()
	f.BoolVarP(&a.opts.detectOnly, "detect-only", "d", false,
		"only print what was detected; don't connect a client\n(e.g. portal -d example.com:443)")
	f.BoolVar(&a.opts.jsonOut, "json", false,
		"print the detection result as JSON; implies --detect-only\n(e.g. portal --json db:5432 | jq .service)")
	f.DurationVarP(&a.opts.timeout, "timeout", "t", 10*time.Second,
		"overall time limit for detection\n(e.g. --timeout 3s, --timeout 500ms)")
	f.BoolVarP(&a.opts.verbose, "verbose", "v", false,
		"show which probes ran and what they saw, on stderr\n(e.g. portal -v server:22)")
	f.BoolVarP(&a.opts.dryRun, "dry-run", "n", false,
		"print the client command instead of running it\n(e.g. portal -n db:5432 -- -U admin)")

	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		hint := "run 'portal --help' for usage"
		if strings.Contains(err.Error(), "unknown") {
			hint = "to pass options to the client, put them after --, e.g. portal db:5432 -- -U admin"
		}
		return usageError(err, hint)
	})
	return cmd
}

// Execute runs portal with the process's arguments and standard streams and
// returns the exit code.
func Execute(version string) int {
	streams := DefaultStreams()
	cmd := NewRootCommand(version, streams)
	err := cmd.ExecuteContext(context.Background())
	return report(streams.Err, term.Style{Enabled: streams.ErrColor}, err)
}

// splitArgs separates the target arguments from the arguments after "--",
// which are passed through to the client.
func splitArgs(args []string, dash int) (targetArgs, extra []string) {
	if dash < 0 {
		return args, nil
	}
	return args[:dash], args[dash:]
}

func (a *app) run(ctx context.Context, targetArgs, extra []string) error {
	t, err := target.Parse(targetArgs)
	if err != nil {
		return usageError(err, "")
	}
	if a.opts.jsonOut {
		a.opts.detectOnly = true
	}
	if a.opts.timeout <= 0 {
		return usageError(fmt.Errorf("invalid --timeout %v", a.opts.timeout), "use a positive duration, e.g. --timeout 5s")
	}

	if err := a.checkReachable(ctx, t); err != nil {
		return err
	}
	if a.opts.detectOnly {
		fmt.Fprintf(a.streams.Out, "No known service detected on %s\n", t)
		return nil
	}
	return a.rawSession(ctx, t, false, false)
}

// checkReachable dials t once so connection problems are reported with exit
// code 1 before anything else happens.
func (a *app) checkReachable(ctx context.Context, t target.Target) error {
	d := net.Dialer{Timeout: a.opts.timeout}
	conn, err := d.DialContext(ctx, "tcp", t.Addr())
	if err != nil {
		return connectionError(t, err)
	}
	return conn.Close()
}

func (a *app) rawSession(ctx context.Context, t target.Target, useTLS, crlf bool) error {
	kind := "TCP"
	if useTLS {
		kind = "TLS"
	}
	if a.opts.dryRun {
		fmt.Fprintf(a.streams.Out, "(built-in raw %s session to %s)\n", kind, t)
		return nil
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
