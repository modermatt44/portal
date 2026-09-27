package cli

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/modermatt44/portal/internal/detect"
)

// maxPromptAttempts is how often an invalid answer is tolerated.
const maxPromptAttempts = 3

// rawChoice is the pseudo-result that selects portal's raw session.
func rawChoice(tls *detect.TLSInfo) detect.Result {
	return detect.Result{Service: detect.Unknown, TLS: tls}
}

func rawLabel(tls bool) string {
	if tls {
		return "raw TLS session"
	}
	return "raw TCP session"
}

// choose asks the user to pick one of the report's candidates or a raw
// session. Without a terminal it returns a usage error that explains how
// to choose with --service.
func (a *app) choose(rep *detect.Report) (detect.Result, error) {
	cands := rep.Candidates
	if !a.streams.InTTY {
		names := make([]string, len(cands))
		for i, c := range cands {
			names[i] = c.Service.DisplayName()
		}
		return detect.Result{}, usageError(
			fmt.Errorf("can't tell for sure which service runs on %s (%s)", rep.Target, strings.Join(names, " or ")),
			fmt.Sprintf("pick one with --service, e.g. portal --service %s %s, or --service raw", cands[0].Service, rep.Target))
	}

	w := a.streams.Err
	s := a.err
	if len(cands) == 1 {
		fmt.Fprintf(w, "%s Couldn't confirm the service on %s:\n", s.Yellow("?"), rep.Target)
	} else {
		fmt.Fprintf(w, "%s Several services could be on %s:\n", s.Yellow("?"), rep.Target)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, c := range cands {
		fmt.Fprintf(tw, "  %d) %s\t%s\t%s\n", i+1, c.Label(), s.Dim(c.Confidence.String()), s.Dim(c.Evidence))
	}
	fmt.Fprintf(tw, "  %d) %s\t\t\n", len(cands)+1, rawLabel(rep.TLS != nil))
	tw.Flush()

	n := len(cands) + 1
	for range maxPromptAttempts {
		fmt.Fprintf(w, "Choose 1-%d [1], or q to quit: ", n)
		answer, err := a.readLine()
		if err != nil {
			fmt.Fprintln(w)
			return detect.Result{}, usageError(errors.New("no choice made"), "pick a service with --service to skip the question")
		}
		switch answer = strings.TrimSpace(answer); {
		case answer == "":
			return cands[0], nil
		case strings.EqualFold(answer, "q"):
			return detect.Result{}, usageError(errors.New("aborted"), "")
		}
		i, err := strconv.Atoi(answer)
		switch {
		case err != nil || i < 1 || i > n:
			fmt.Fprintf(w, "%s please enter a number between 1 and %d\n", s.Red("✗"), n)
		case i == n:
			return rawChoice(rep.TLS), nil
		default:
			return cands[i-1], nil
		}
	}
	return detect.Result{}, usageError(errors.New("no valid choice made"), "pick a service with --service to skip the question")
}

// confirm asks a yes/no question and returns def when the user just
// presses Enter. It returns false without asking when there is no
// terminal.
func (a *app) confirm(question string, def bool) bool {
	if !a.streams.InTTY {
		return false
	}
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	fmt.Fprintf(a.streams.Err, "%s %s ", question, hint)
	answer, err := a.readLine()
	if err != nil {
		fmt.Fprintln(a.streams.Err)
		return false
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "":
		return def
	case "y", "yes":
		return true
	default:
		return false
	}
}

// readLine reads one line from stdin without buffering past it, so that
// nothing typed later is lost when stdin is handed to a client.
func (a *app) readLine() (string, error) {
	var sb strings.Builder
	var b [1]byte
	for {
		n, err := a.streams.In.Read(b[:])
		if n == 1 {
			if b[0] == '\n' {
				return strings.TrimSuffix(sb.String(), "\r"), nil
			}
			sb.WriteByte(b[0])
		}
		if err != nil {
			if err == io.EOF && sb.Len() > 0 {
				return sb.String(), nil
			}
			return "", err
		}
	}
}
