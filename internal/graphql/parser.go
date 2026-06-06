package graphql

import (
	"encoding/json"
	"strings"
	"unicode"
)

// ExtractOperationName parses a GraphQL request body and returns the operation
// name, if present.
//
// It handles two body shapes:
//
//  1. A JSON GraphQL request envelope, e.g.
//     {"operationName":"GetUser","query":"query GetUser { ... }"}.
//     The top-level "operationName" field takes precedence; if it is absent or
//     empty, the embedded "query" document is parsed.
//  2. A raw GraphQL document, e.g. `query GetUser { ... }`,
//     `mutation CreateUser { ... }`, `subscription OnEvent { ... }`, or a
//     query-shorthand anonymous document `{ ... }`.
//
// Anonymous operations (shorthand `{ ... }` or a bare `query { ... }` with no
// name) yield an empty string. The parse is dependency-free and tolerant: on
// any malformed input it returns "".
func ExtractOperationName(body []byte) string {
	name, _ := parse(body)
	return name
}

// ExtractOperation returns both the operation name and the operation type
// ("query", "mutation", or "subscription") for a GraphQL request body. The
// type is "query" for the query-shorthand form. For inputs that cannot be
// parsed as a GraphQL document, the type is "".
func ExtractOperation(body []byte) (name, opType string) {
	return parse(body)
}

func parse(body []byte) (name, opType string) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "", ""
	}

	// JSON envelope: {"operationName":...,"query":...}
	if trimmed[0] == '{' {
		var env struct {
			OperationName string `json:"operationName"`
			Query         string `json:"query"`
		}
		if err := json.Unmarshal([]byte(trimmed), &env); err == nil {
			if env.OperationName != "" {
				// Determine type from the embedded query document when available.
				_, t := parseDocument(env.Query)
				return env.OperationName, t
			}
			if env.Query != "" {
				return parseDocument(env.Query)
			}
			// Valid JSON envelope but no name/query: treat as anonymous.
			return "", "query"
		}
		// Not valid JSON; fall through and try raw-document parsing (handles
		// the query-shorthand `{ ... }` form).
	}

	return parseDocument(trimmed)
}

// parseDocument parses a raw GraphQL document string and returns the first
// operation's name and type. It scans past leading comments/whitespace, reads
// the operation keyword (defaulting to "query" for the shorthand `{ ... }`
// form), then reads the optional operation name.
func parseDocument(doc string) (name, opType string) {
	r := strings.NewReader(doc)
	tok, ok := nextToken(r)
	if !ok {
		return "", ""
	}

	switch tok {
	case "{":
		// Query shorthand: anonymous query.
		return "", "query"
	case "query", "mutation", "subscription":
		opType = tok
	default:
		// Not a recognizable GraphQL operation document.
		return "", ""
	}

	// Read the next token: either the operation name, the variable/directive
	// list, or the selection set opener "{".
	next, ok := nextToken(r)
	if !ok {
		return "", opType
	}
	if isName(next) {
		return next, opType
	}
	// Anonymous operation (e.g. `query { ... }` or `query($x: Int) { ... }`).
	return "", opType
}

// nextToken returns the next significant token from r, skipping insignificant
// characters (whitespace, commas) and GraphQL line comments (# ...). A token is
// either a contiguous run of name characters [_A-Za-z0-9] or a single
// punctuation rune.
func nextToken(r *strings.Reader) (string, bool) {
	for {
		ch, _, err := r.ReadRune()
		if err != nil {
			return "", false
		}
		if ch == '#' {
			// Skip to end of line.
			for {
				c, _, err := r.ReadRune()
				if err != nil {
					return "", false
				}
				if c == '\n' {
					break
				}
			}
			continue
		}
		if isIgnored(ch) {
			continue
		}
		if isNameStart(ch) || unicode.IsDigit(ch) {
			var b strings.Builder
			b.WriteRune(ch)
			for {
				c, _, err := r.ReadRune()
				if err != nil {
					break
				}
				if isNameChar(c) {
					b.WriteRune(c)
					continue
				}
				_ = r.UnreadRune()
				break
			}
			return b.String(), true
		}
		// Single punctuation rune.
		return string(ch), true
	}
}

func isIgnored(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ',' || r == '\uFEFF'
}

func isNameStart(r rune) bool {
	return r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

func isNameChar(r rune) bool {
	return isNameStart(r) || (r >= '0' && r <= '9')
}

// isName reports whether tok is a valid GraphQL name (used to distinguish an
// operation name from punctuation like "(" or "{").
func isName(tok string) bool {
	if tok == "" {
		return false
	}
	for i, r := range tok {
		if i == 0 {
			if !isNameStart(r) {
				return false
			}
			continue
		}
		if !isNameChar(r) {
			return false
		}
	}
	return true
}
