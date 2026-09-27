package config

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// This file implements the small subset of TOML (https://toml.io) that the
// config file needs:
//
//	# comments
//	[table]
//	[table."quoted.key"]
//	key = "basic string"
//	"quoted key" = 'literal string'
//	number = 42
//	flag = true
//
// Arrays, inline tables, multi-line strings, dates and dotted keys are not
// supported and produce an error that names the line.

// table is one [table] section with its key/value pairs.
type table struct {
	path []string
	line int
	keys map[string]entry
}

// entry is a value and the line it was defined on.
type entry struct {
	value any // string, int64 or bool
	line  int
}

// SyntaxError reports a problem in the config file.
type SyntaxError struct {
	Line int
	Msg  string
}

// Error implements the error interface.
func (e *SyntaxError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

// parseTOML reads the document into tables. Keys before the first header
// belong to a table with an empty path.
func parseTOML(r io.Reader) ([]*table, error) {
	root := &table{keys: map[string]entry{}}
	tables := []*table{root}
	seen := map[string]bool{"": true}
	cur := root

	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if n == 1 {
			line = strings.TrimPrefix(line, string(rune(0xFEFF))) // byte order mark
		}
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			if strings.HasPrefix(line, "[[") {
				return nil, &SyntaxError{n, "arrays of tables ([[...]]) are not supported"}
			}
			path, rest, err := parseKeyPath(line[1:], ']')
			if err != nil {
				return nil, &SyntaxError{n, err.Error()}
			}
			if err := expectEnd(rest); err != nil {
				return nil, &SyntaxError{n, err.Error()}
			}
			id := strings.Join(path, "\x00")
			if seen[id] {
				return nil, &SyntaxError{n, fmt.Sprintf("table [%s] is defined twice", strings.Join(path, "."))}
			}
			seen[id] = true
			cur = &table{path: path, line: n, keys: map[string]entry{}}
			tables = append(tables, cur)
			continue
		}

		path, rest, err := parseKeyPath(line, '=')
		if err != nil {
			return nil, &SyntaxError{n, err.Error()}
		}
		if len(path) != 1 {
			return nil, &SyntaxError{n, "dotted keys are not supported; use a [table] header instead"}
		}
		value, rest, err := parseValue(strings.TrimSpace(rest))
		if err != nil {
			return nil, &SyntaxError{n, err.Error()}
		}
		if err := expectEnd(rest); err != nil {
			return nil, &SyntaxError{n, err.Error()}
		}
		if _, dup := cur.keys[path[0]]; dup {
			return nil, &SyntaxError{n, fmt.Sprintf("key %q is defined twice", path[0])}
		}
		cur.keys[path[0]] = entry{value: value, line: n}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return tables, nil
}

// parseKeyPath parses dot-separated bare or quoted keys up to the
// terminator and returns the keys and the text after the terminator.
func parseKeyPath(s string, term byte) ([]string, string, error) {
	var path []string
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return nil, "", fmt.Errorf("expected a key")
		}
		var key string
		switch s[0] {
		case '"', '\'':
			v, rest, err := parseString(s)
			if err != nil {
				return nil, "", err
			}
			key, s = v, rest
		default:
			end := strings.IndexFunc(s, func(r rune) bool {
				return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-')
			})
			if end == 0 {
				return nil, "", fmt.Errorf("unexpected %q in key", s[0])
			}
			if end < 0 {
				end = len(s)
			}
			key, s = s[:end], s[end:]
		}
		path = append(path, key)
		s = strings.TrimLeft(s, " \t")
		switch {
		case s == "":
			return nil, "", fmt.Errorf("expected %q after key %q", term, key)
		case s[0] == '.':
			s = s[1:]
		case s[0] == term:
			return path, s[1:], nil
		default:
			return nil, "", fmt.Errorf("expected %q after key %q, found %q", term, key, s[0])
		}
	}
}

// parseValue parses a string, integer or boolean at the start of s.
func parseValue(s string) (any, string, error) {
	switch {
	case s == "":
		return nil, "", fmt.Errorf("missing value after '='")
	case s[0] == '"' || s[0] == '\'':
		if strings.HasPrefix(s, `"""`) || strings.HasPrefix(s, "'''") {
			return nil, "", fmt.Errorf("multi-line strings are not supported")
		}
		return parseString(s)
	case s[0] == '[' || s[0] == '{':
		return nil, "", fmt.Errorf("arrays and inline tables are not supported")
	}
	end := strings.IndexAny(s, " \t#")
	if end < 0 {
		end = len(s)
	}
	word, rest := s[:end], s[end:]
	switch word {
	case "true":
		return true, rest, nil
	case "false":
		return false, rest, nil
	}
	n, err := strconv.ParseInt(strings.ReplaceAll(word, "_", ""), 10, 64)
	if err != nil {
		return nil, "", fmt.Errorf("invalid value %q; strings need quotes, e.g. \"%s\"", word, word)
	}
	return n, rest, nil
}

// parseString parses a basic ("...") or literal ('...') string.
func parseString(s string) (string, string, error) {
	q := s[0]
	var sb strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == q:
			return sb.String(), s[i+1:], nil
		case c == '\\' && q == '"':
			i++
			if i >= len(s) {
				return "", "", fmt.Errorf("unterminated string")
			}
			switch s[i] {
			case '"', '\\':
				sb.WriteByte(s[i])
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			case 'r':
				sb.WriteByte('\r')
			case 'u':
				if i+4 >= len(s) {
					return "", "", fmt.Errorf(`invalid \u escape`)
				}
				r, err := strconv.ParseUint(s[i+1:i+5], 16, 32)
				if err != nil {
					return "", "", fmt.Errorf(`invalid \u escape`)
				}
				sb.WriteRune(rune(r))
				i += 4
			default:
				return "", "", fmt.Errorf(`invalid escape "\%c"; use "\\" for a backslash or a 'literal string'`, s[i])
			}
		default:
			sb.WriteByte(c)
		}
	}
	return "", "", fmt.Errorf("unterminated string")
}

// expectEnd checks that only whitespace or a comment follows a statement.
func expectEnd(rest string) error {
	rest = strings.TrimSpace(rest)
	if rest != "" && rest[0] != '#' {
		return fmt.Errorf("unexpected %q at end of line", rest)
	}
	return nil
}
