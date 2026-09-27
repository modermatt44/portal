// Package term detects interactive terminals and applies ANSI colors when
// they are appropriate.
package term

import (
	"os"
)

// IsTerminal reports whether f is connected to an interactive terminal.
func IsTerminal(f *os.File) bool {
	return isTerminal(f)
}

// ColorEnabled reports whether colored output should be written to f. Color
// is disabled when f is not a terminal or when the NO_COLOR environment
// variable is set to a non-empty value (see https://no-color.org).
func ColorEnabled(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return IsTerminal(f) && enableVirtualTerminal(f)
}

// Style wraps text in ANSI escape sequences when enabled. The zero value
// produces plain text.
type Style struct {
	// Enabled turns color on.
	Enabled bool
}

func (s Style) wrap(code, text string) string {
	if !s.Enabled || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

// Bold renders text in bold.
func (s Style) Bold(text string) string { return s.wrap("1", text) }

// Dim renders text dimmed, for secondary information.
func (s Style) Dim(text string) string { return s.wrap("2", text) }

// Green renders text in green, used for success.
func (s Style) Green(text string) string { return s.wrap("32", text) }

// Yellow renders text in yellow, used for warnings and questions.
func (s Style) Yellow(text string) string { return s.wrap("33", text) }

// Red renders text in red, used for errors.
func (s Style) Red(text string) string { return s.wrap("31", text) }

// Cyan renders text in cyan, used for commands and highlights.
func (s Style) Cyan(text string) string { return s.wrap("36", text) }
