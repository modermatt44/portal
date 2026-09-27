package detect

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

// This file holds helpers shared by the line-based text protocols.

// maxQuote caps how much of a banner is shown in evidence and logs.
const maxQuote = 100

// quoteBanner returns b as a quoted, printable string, truncated if long.
func quoteBanner(b []byte) string {
	b = bytes.TrimRight(b, "\r\n")
	if len(b) > maxQuote {
		return strconv.Quote(string(b[:maxQuote])) + "…"
	}
	return strconv.Quote(string(b))
}

// bannerLines splits a text banner into lines without line terminators.
func bannerLines(b []byte) []string {
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimRight(l, "\r")
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// firstLine returns the first non-empty line of b.
func firstLine(b []byte) string {
	if lines := bannerLines(b); len(lines) > 0 {
		return lines[0]
	}
	return ""
}

// containsFold reports whether substr is within s, ignoring case.
func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// versionToken returns the leading version-like part of s, such as "4.96"
// from "4.96 Mon, 1 Jan" or "3.0.5" from "3.0.5)". It returns "" if s does
// not start with a digit.
func versionToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || !unicode.IsDigit(rune(s[0])) {
		return ""
	}
	end := strings.IndexFunc(s, func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_')
	})
	if end < 0 {
		end = len(s)
	}
	return strings.TrimRight(s[:end], ".-_")
}

// findProduct looks for the first of the known product names in line,
// ignoring case, and returns its canonical spelling and the version that
// directly follows it, if any.
func findProduct(line string, known []string) (product, version string) {
	lower := strings.ToLower(line)
	for _, name := range known {
		i := strings.Index(lower, strings.ToLower(name))
		if i < 0 {
			continue
		}
		rest := line[i+len(name):]
		rest = strings.TrimLeft(rest, " /v")
		return name, versionToken(rest)
	}
	return "", ""
}

// lineConn reads CRLF-terminated lines from a connection.
type lineConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func newLineConn(conn net.Conn) *lineConn {
	return &lineConn{conn: conn, r: bufio.NewReader(conn)}
}

// send writes one command followed by CRLF.
func (c *lineConn) send(format string, args ...any) error {
	_, err := fmt.Fprintf(c.conn, format+"\r\n", args...)
	return err
}

// readLine reads one line and strips the terminator.
func (c *lineConn) readLine() (string, error) {
	line, err := c.r.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readReply reads an SMTP/FTP-style reply: "250-first", "250-second",
// "250 last". FTP may also send continuation lines without a code
// (RFC 959 section 4.2). It returns the code and the text of every line.
func (c *lineConn) readReply() (int, []string, error) {
	var lines []string
	for {
		line, err := c.readLine()
		if err != nil {
			return 0, lines, err
		}
		if len(line) < 3 {
			lines = append(lines, line)
			continue
		}
		code, convErr := strconv.Atoi(line[:3])
		if convErr != nil {
			lines = append(lines, strings.TrimSpace(line))
			continue
		}
		text := ""
		if len(line) > 4 {
			text = line[4:]
		}
		lines = append(lines, text)
		if len(line) == 3 || line[3] == ' ' {
			return code, lines, nil
		}
	}
}

// replyCode parses the three-digit code at the start of an SMTP/FTP line.
func replyCode(line string) (int, bool) {
	if len(line) < 3 {
		return 0, false
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil || (len(line) > 3 && line[3] != ' ' && line[3] != '-') {
		return 0, false
	}
	return code, true
}
