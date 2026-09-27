package cli

import (
	"errors"
	"syscall"
)

// wsaeconnrefused is Windows' "connection refused" error code, which is not
// equal to syscall.ECONNREFUSED on that platform.
const wsaeconnrefused syscall.Errno = 10061

func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, wsaeconnrefused)
}
