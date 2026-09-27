//go:build unix

package clients

import (
	"errors"
	"os"
	"syscall"
)

// Exec replaces the portal process with cmd, so the client gets the
// terminal, signals and exit status directly. It only returns on failure.
func Exec(cmd Command) error {
	if cmd.Builtin || cmd.Path == "" {
		return errors.New("clients: Exec needs an external program")
	}
	return syscall.Exec(cmd.Path, cmd.Argv(), os.Environ())
}
