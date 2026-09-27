package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/modermatt44/portal/internal/term"
)

// Exit codes returned by portal.
const (
	// ExitOK means the command succeeded.
	ExitOK = 0
	// ExitConnection means the target could not be reached.
	ExitConnection = 1
	// ExitUsage means the command line was invalid or the user aborted a choice.
	ExitUsage = 2
	// ExitNoClient means no client program is available for the service.
	ExitNoClient = 3
)

// Error is an error that carries an exit code and a hint telling the user
// what to do next.
type Error struct {
	// Code is the process exit code.
	Code int
	// Err describes what went wrong.
	Err error
	// Hint suggests the next step. It may be empty.
	Hint string
}

func (e *Error) Error() string { return e.Err.Error() }

func (e *Error) Unwrap() error { return e.Err }

func usageError(err error, hint string) *Error {
	return &Error{Code: ExitUsage, Err: err, Hint: hint}
}

// exitStatus is returned when a child process exits with a non-zero status
// and portal should exit the same way without printing anything.
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("client exited with status %d", int(e)) }

// report prints err to w and returns the exit code it maps to.
func report(w io.Writer, style term.Style, err error) int {
	if err == nil {
		return ExitOK
	}
	var status exitStatus
	if errors.As(err, &status) {
		return int(status)
	}
	code := ExitUsage
	hint := ""
	var e *Error
	if errors.As(err, &e) {
		code, hint = e.Code, e.Hint
	}
	fmt.Fprintf(w, "%s %s\n", style.Red("✗"), err)
	if hint != "" {
		fmt.Fprintf(w, "  %s %s\n", style.Dim("→"), hint)
	}
	return code
}
