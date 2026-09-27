// Package cli implements portal's command-line interface: argument parsing,
// output, the interactive chooser and the hand-off to client programs.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/modermatt44/portal/internal/clients"
	"github.com/modermatt44/portal/internal/config"
	"github.com/modermatt44/portal/internal/detect"
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
	service    string
	configPath string
}

type app struct {
	opts     options
	streams  Streams
	out      term.Style // style for Out
	err      term.Style // style for Err
	cfg      *config.Config
	resolver clients.Resolver
	// timeoutSet reports whether --timeout was given explicitly.
	timeoutSet bool
	// start is when the command started, for verbose timings.
	start time.Time
}

const longHelp = `portal connects to a TCP port, figures out which service is running there,
and hands your terminal over to the right client (psql, ssh, redis-cli, ...).

Detection runs in this order, each step with a short timeout:
  1. wait briefly for a banner (SSH, SMTP, FTP, IMAP, POP3, MySQL send one)
  2. try a TLS handshake and, if it works, detect again inside the tunnel
  3. send active probes (HTTP, Redis, PostgreSQL, MongoDB)
  4. fall back to the well-known port number as an unverified hint

Unknown services open a raw interactive session (like nc), over TLS if the
port speaks TLS. If detection is ambiguous, portal asks which service to use.

Configuration (optional): ` + "`" + `%s` + "`" + `
  [clients]                      # preferred client per service
  postgresql = "pgcli"
  [hosts."cache.local:6380"]     # skip detection for one endpoint
  service = "redis"

Exit codes:
  0  success (or the client's own exit code once it has started)
  1  connection error (host unreachable, port closed, timeout)
  2  usage error, or no choice was made at a prompt
  3  no client program is available for the detected service

Only probe hosts you are authorized to test.`

const examples = `  # Detect the service and open the matching client
  portal db.local:5432            # PostgreSQL → psql -h db.local -p 5432
  portal server:22                # SSH        → ssh -p 22 server
  portal example.com:443          # HTTPS      → curl -v https://example.com
  portal 10.0.0.5:6379            # Redis      → redis-cli -h 10.0.0.5 -p 6379

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

  # Skip detection when you already know the service
  portal --service redis cache.local:6380

  # See which probes ran and what they saw, with a longer time limit
  portal -v --timeout 20s slow.example.com:8080`

// NewRootCommand builds the portal command. version is shown by --version.
func NewRootCommand(version string, streams Streams) *cobra.Command {
	return newRootCommand(version, streams, clients.Resolver{})
}

func newRootCommand(version string, streams Streams, resolver clients.Resolver) *cobra.Command {
	a := &app{
		streams:  streams,
		out:      term.Style{Enabled: streams.OutColor},
		err:      term.Style{Enabled: streams.ErrColor},
		resolver: resolver,
	}
	configHelp := config.DefaultPath()
	if configHelp == "" {
		configHelp = "~/.config/portal/config.toml"
	}
	cmd := &cobra.Command{
		Use:                   "portal [flags] <host:port | host port> [-- client args...]",
		DisableFlagsInUseLine: true,
		Short:                 "Detect the service on a TCP port and open the right client",
		Long:                  fmt.Sprintf(longHelp, configHelp),
		Example:               examples,
		Version:               version,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usageError(errors.New("missing target"), "try: portal db.local:5432, or see portal --help")
			}
			return nil
		},
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			a.timeoutSet = cmd.Flags().Changed("timeout")
			a.start = time.Now()
			targetArgs, extra := splitArgs(args, cmd.ArgsLenAtDash())
			return a.run(cmd.Context(), targetArgs, extra)
		},
	}
	cmd.SetIn(streams.In)
	cmd.SetOut(streams.Out)
	cmd.SetErr(streams.Err)

	f := cmd.Flags()
	f.SortFlags = false
	f.BoolVarP(&a.opts.detectOnly, "detect-only", "d", false,
		"only print what was detected; don't connect a client\n(e.g. portal -d example.com:443)")
	f.BoolVar(&a.opts.jsonOut, "json", false,
		"print the detection result as JSON; implies --detect-only\n(e.g. portal --json db:5432 | jq .service)")
	f.BoolVarP(&a.opts.dryRun, "dry-run", "n", false,
		"print the client command instead of running it\n(e.g. portal -n db:5432 -- -U admin)")
	f.DurationVarP(&a.opts.timeout, "timeout", "t", detect.DefaultTimeout,
		"overall time limit for detection\n(e.g. --timeout 3s, --timeout 500ms)")
	f.BoolVarP(&a.opts.verbose, "verbose", "v", false,
		"show which probes ran and what they saw, on stderr\n(e.g. portal -v server:22)")
	f.StringVarP(&a.opts.service, "service", "s", "",
		"skip detection and treat the port as this service\n(one of: "+serviceNames()+")\n(e.g. portal -s redis cache.local:6380)")
	f.StringVar(&a.opts.configPath, "config", "",
		"read this config file instead of the default\n(e.g. --config ./portal.toml; or set "+config.EnvPath+")")

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
	if a.opts.service != "" && a.opts.detectOnly {
		return usageError(errors.New("--service skips detection, so it can't be combined with --detect-only"), "drop one of the two flags")
	}
	if err := a.loadConfig(); err != nil {
		return err
	}

	// An explicit --service wins over the config file, which wins over
	// detection.
	if a.opts.service != "" {
		choice, err := parseService(a.opts.service)
		if err != nil {
			return err
		}
		return a.handoff(ctx, t, choice, "set with --service", extra)
	}
	if h, ok := a.cfg.Host(t); ok && h.Service != "" && !a.opts.detectOnly {
		choice, err := parseService(h.Service)
		if err != nil {
			return err
		}
		a.logf("config: %s is set to %s", t, h.Service)
		return a.handoff(ctx, t, choice, "set in config", extra)
	}

	rep, err := a.detect(ctx, t)
	if err != nil {
		return err
	}
	if a.opts.detectOnly {
		return a.printDetection(rep, extra)
	}

	choice, ok := rep.Best()
	switch {
	case ok:
	case len(rep.Candidates) > 0:
		if choice, err = a.choose(rep); err != nil {
			return err
		}
	default:
		choice = rawChoice(rep.TLS)
	}
	return a.handoff(ctx, t, choice, "detected", extra)
}

// loadConfig reads the config file named by --config, or the default one
// if it exists.
func (a *app) loadConfig() error {
	path, explicit := a.opts.configPath, a.opts.configPath != ""
	if !explicit {
		path = config.DefaultPath()
	}
	cfg, err := config.Load(path, explicit)
	if err != nil {
		return usageError(fmt.Errorf("config: %w", err), "fix the config file, or point --config at another one")
	}
	a.cfg = cfg
	if cfg.Path != "" {
		a.logf("config: loaded %s", cfg.Path)
	}
	return nil
}

// printDetection writes the --detect-only report, including the client
// command portal would run.
func (a *app) printDetection(rep *detect.Report, extra []string) error {
	choice, ok := rep.Best()
	if !ok && len(rep.Candidates) == 0 {
		choice, ok = rawChoice(rep.TLS), true
	}
	var argv []string
	client := ""
	if ok {
		cmd, err := a.resolver.Resolve(a.request(rep.Target, choice, extra))
		var missing *clients.MissingError
		switch {
		case errors.As(err, &missing):
			argv = cmd.Argv()
			client = fmt.Sprintf("%s  %s", cmd, a.out.Yellow("(not installed: "+missing.Hint+")"))
		case err == nil:
			argv = cmd.Argv()
			client = cmd.String()
		}
	}
	if a.opts.jsonOut {
		return writeJSON(a.streams.Out, rep, argv)
	}
	printReport(a.streams.Out, a.out, rep, client)
	return nil
}

// detect runs service detection with timeouts from the flags and config,
// logging each step to stderr in verbose mode.
func (a *app) detect(ctx context.Context, t target.Target) (*detect.Report, error) {
	opts := detect.Options{
		Timeout:       a.opts.timeout,
		BannerTimeout: a.cfg.BannerTimeout,
		TLSTimeout:    a.cfg.TLSTimeout,
		ProbeTimeout:  a.cfg.ProbeTimeout,
	}
	if !a.timeoutSet && a.cfg.Timeout > 0 {
		opts.Timeout = a.cfg.Timeout
	}
	if a.opts.verbose {
		opts.Logf = a.logf
	}
	rep, err := detect.Detect(ctx, t, opts)
	var ce *detect.ConnError
	if errors.As(err, &ce) {
		return nil, connectionError(t, ce.Err)
	}
	return rep, err
}

// logf writes a verbose log line to stderr with the time since start.
func (a *app) logf(format string, args ...any) {
	if !a.opts.verbose {
		return
	}
	ms := time.Since(a.start).Milliseconds()
	fmt.Fprintf(a.streams.Err, "%s %s\n", a.err.Dim(fmt.Sprintf("%5dms", ms)), fmt.Sprintf(format, args...))
}

// serviceNames lists the values --service accepts, for help and errors.
func serviceNames() string {
	var names []string
	for _, s := range detect.Services() {
		names = append(names, string(s))
	}
	return strings.Join(append(names, "raw", "tls"), ", ")
}

// parseService turns a --service value (or a config override) into a
// result to hand off to. "raw" and "tls" select portal's raw session.
func parseService(name string) (detect.Result, error) {
	r := detect.Result{Confidence: detect.Confirmed}
	switch n := strings.ToLower(strings.TrimSpace(name)); n {
	case "raw", "tcp":
		r.Service = detect.Unknown
	case "tls":
		r.Service = detect.Unknown
		r.TLS = &detect.TLSInfo{}
	default:
		s, ok := detect.ParseService(n)
		if !ok {
			return detect.Result{}, usageError(fmt.Errorf("unknown service %q", name), "use one of: "+serviceNames())
		}
		r.Service = s
		if s == detect.HTTPS {
			r.TLS = &detect.TLSInfo{}
		}
	}
	return r, nil
}
