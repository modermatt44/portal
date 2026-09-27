// Package clients maps detected services to the client programs that talk
// to them, finds those programs, and hands the terminal over to them.
package clients

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/modermatt44/portal/internal/detect"
	"github.com/modermatt44/portal/internal/target"
)

// Request describes the session the user wants.
type Request struct {
	// Target is the endpoint to connect to.
	Target target.Target
	// Service is the protocol spoken there; detect.Unknown selects a raw
	// session.
	Service detect.Service
	// TLS means the port speaks TLS from the first byte.
	TLS bool
	// StartTLS means the server offers an in-protocol TLS upgrade.
	StartTLS bool
	// Extra are arguments passed through to the client after "--".
	Extra []string
	// Preferred is a client command line from the config file, such as
	// "pgcli" or "usql pg://{host}:{port}". Empty selects the default.
	Preferred string
}

// Command is a resolved way to open an interactive session.
type Command struct {
	// Name is the program name shown to the user, e.g. "psql". It is empty
	// for the built-in raw session.
	Name string
	// Path is the program's absolute path. It is empty if the program was
	// not found.
	Path string
	// Args are the program's arguments, without the program name.
	Args []string
	// Builtin selects portal's own raw session instead of a program.
	Builtin bool
	// TLS wraps the built-in session in TLS.
	TLS bool
	// CRLF makes the built-in session send CRLF line endings.
	CRLF bool
}

// String returns the command line in a form that can be pasted into a
// shell, or a description of the built-in session.
func (c Command) String() string {
	if c.Builtin {
		if c.TLS {
			return "(built-in raw TLS session)"
		}
		return "(built-in raw TCP session)"
	}
	words := append([]string{c.Name}, c.Args...)
	for i, w := range words {
		words[i] = shellQuote(w)
	}
	return strings.Join(words, " ")
}

// Argv returns the program name followed by its arguments, or nil for the
// built-in session.
func (c Command) Argv() []string {
	if c.Builtin {
		return nil
	}
	return append([]string{c.Name}, c.Args...)
}

// MissingError reports that no client program for a service is installed.
type MissingError struct {
	// Service is the service that needs a client.
	Service detect.Service
	// Tried lists the programs that were looked for, preferred first.
	Tried []string
	// Hint says how to install the preferred program on this OS.
	Hint string
}

func (e *MissingError) Error() string {
	msg := fmt.Sprintf("%s is not installed", e.Tried[0])
	if len(e.Tried) > 1 {
		msg += fmt.Sprintf(" (also looked for %s)", strings.Join(e.Tried[1:], ", "))
	}
	return msg
}

// Resolver finds the client program for a request. The zero value uses
// exec.LookPath and the current operating system.
type Resolver struct {
	// LookPath finds a program on PATH. Nil means exec.LookPath.
	LookPath func(file string) (string, error)
	// GOOS selects install hints. Empty means runtime.GOOS.
	GOOS string
}

func (r Resolver) lookPath(file string) (string, error) {
	if r.LookPath != nil {
		return r.LookPath(file)
	}
	return exec.LookPath(file)
}

func (r Resolver) goos() string {
	if r.GOOS != "" {
		return r.GOOS
	}
	return runtime.GOOS
}

// Resolve returns the command to run for req: the preferred client if one
// is configured, otherwise the first installed default client. If no
// suitable program is installed it returns the command it would have run
// (with an empty Path) and a *MissingError.
func (r Resolver) Resolve(req Request) (Command, error) {
	if req.Preferred != "" {
		return r.resolvePreferred(req)
	}
	candidates := Clients(req)
	if len(candidates) == 0 {
		return Command{}, fmt.Errorf("no client is known for %s", req.Service.DisplayName())
	}
	var tried []string
	for _, c := range candidates {
		if c.Builtin {
			return Command{Builtin: true, TLS: req.TLS, CRLF: c.CRLF}, nil
		}
		path, err := r.lookPath(c.Program)
		if err == nil {
			return Command{Name: c.Program, Path: path, Args: append(c.Args(req), req.Extra...)}, nil
		}
		tried = append(tried, c.Program)
	}
	first := candidates[0]
	return Command{Name: first.Program, Args: append(first.Args(req), req.Extra...)},
		&MissingError{Service: req.Service, Tried: tried, Hint: first.InstallHint(r.goos())}
}

// resolvePreferred handles a client command line from the config file. A
// bare program name that portal knows gets its usual arguments; anything
// else is used as a template with {host}, {port} and {addr} placeholders.
func (r Resolver) resolvePreferred(req Request) (Command, error) {
	words, err := splitWords(req.Preferred)
	if err != nil || len(words) == 0 {
		return Command{}, fmt.Errorf("invalid client command %q in the config file: %v", req.Preferred, err)
	}
	program := words[0]
	var args []string
	known, isKnown := lookupClient(program)
	if len(words) == 1 && isKnown {
		args = known.Args(req)
	} else {
		repl := strings.NewReplacer("{host}", req.Target.Host, "{port}", strconv.Itoa(req.Target.Port), "{addr}", req.Target.Addr())
		for _, w := range words[1:] {
			args = append(args, repl.Replace(w))
		}
	}
	args = append(args, req.Extra...)
	path, err := r.lookPath(program)
	if err != nil {
		hint := "check the client setting in your config file"
		if isKnown {
			hint = known.InstallHint(r.goos())
		}
		return Command{Name: program, Args: args}, &MissingError{Service: req.Service, Tried: []string{program}, Hint: hint}
	}
	return Command{Name: program, Path: path, Args: args}, nil
}

// httpURL builds the URL for an HTTP(S) request, leaving out default ports.
func httpURL(req Request) string {
	scheme, defPort := "http", 80
	if req.TLS || req.Service == detect.HTTPS {
		scheme, defPort = "https", 443
	}
	host := req.Target.Host
	if req.Target.Port != defPort {
		host = req.Target.Addr()
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host
}

// shellQuote quotes s for POSIX shells if it contains special characters.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=@%+,", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// splitWords splits a command line into words, honoring single and double
// quotes and backslash escapes outside single quotes.
func splitWords(s string) ([]string, error) {
	var (
		words   []string
		cur     strings.Builder
		inWord  bool
		quote   rune
		escaped bool
	)
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && quote != '\'':
			escaped, inWord = true, true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == ' ' || r == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if quote != 0 || escaped {
		return nil, errors.New("unterminated quote or escape")
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

// ExitError reports that a client program exited with a non-zero status.
type ExitError struct {
	// Code is the client's exit status.
	Code int
}

func (e *ExitError) Error() string { return "client exited with status " + strconv.Itoa(e.Code) }
