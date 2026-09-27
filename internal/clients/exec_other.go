//go:build !unix

package clients

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
)

// Exec runs cmd as a child process attached to portal's standard streams
// and waits for it. Windows cannot replace a running process, so portal
// stays alive in the background, ignoring Ctrl+C so the client receives
// it. A non-zero exit status is returned as an *ExitError.
func Exec(cmd Command) error {
	if cmd.Builtin || cmd.Path == "" {
		return errors.New("clients: Exec needs an external program")
	}
	c := exec.Command(cmd.Path, cmd.Args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr

	signal.Ignore(os.Interrupt)
	defer signal.Reset(os.Interrupt)

	err := c.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return &ExitError{Code: ee.ExitCode()}
	}
	return err
}
