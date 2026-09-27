package term

import (
	"os"
	"testing"
)

func TestStyle(t *testing.T) {
	plain := Style{}
	if got := plain.Green("ok"); got != "ok" {
		t.Errorf("disabled Style.Green = %q, want plain text", got)
	}
	color := Style{Enabled: true}
	if got, want := color.Green("ok"), "\x1b[32mok\x1b[0m"; got != want {
		t.Errorf("enabled Style.Green = %q, want %q", got, want)
	}
	if got := color.Red(""); got != "" {
		t.Errorf("enabled Style.Red(\"\") = %q, want empty", got)
	}
}

func TestColorEnabledNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if ColorEnabled(os.Stdout) {
		t.Error("ColorEnabled = true with NO_COLOR set")
	}
}

func TestIsTerminalOnFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "notatty")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if IsTerminal(f) {
		t.Error("IsTerminal(regular file) = true")
	}
}
