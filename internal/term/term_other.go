//go:build !windows

package term

import "os"

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func enableVirtualTerminal(*os.File) bool { return true }
