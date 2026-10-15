package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"unicode"
	"unicode/utf8"
)

// Event values are attacker-controlled by definition: that is what an event
// is. Printing one raw to a terminal would let it carry escape sequences that
// move the cursor, rewrite earlier lines or change the window title. Every
// value shown in a table or in text output goes through safeText first.

// safeText escapes control characters, bidirectional overrides and invalid
// UTF-8, so a value prints as exactly the characters it contains.
func safeText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			fmt.Fprintf(&b, `\x%02x`, r)
		case isBidiControl(r) || (unicode.Is(unicode.Cf, r) && r != 0x200d):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// safeBlock is safeText for multi-line text: newlines and tabs are kept,
// everything else is escaped.
func safeBlock(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i, l := range lines {
		parts := strings.Split(l, "\t")
		for j, p := range parts {
			parts[j] = safeText(p)
		}
		lines[i] = strings.Join(parts, "\t")
	}
	return strings.Join(lines, "\n")
}

func isBidiControl(r rune) bool {
	return (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f || r == 0x061c
}

// truncate shortens s to at most n runes, marking the cut.
func truncate(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	if n <= 3 {
		return string(r[:n])
	}
	return string(r[:n-3]) + "..."
}

// csvSafe guards a cell against spreadsheet formula injection: a cell that
// starts with = + - @ or a tab or carriage return is prefixed with a single
// quote, which spreadsheets show as text. Disable with --raw-csv.
func csvSafe(s string, raw bool) string {
	if raw || s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// table is a tab-aligned table that escapes every cell.
type table struct {
	tw *tabwriter.Writer
}

func newTable(w io.Writer, header ...string) *table {
	t := &table{tw: tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)}
	t.row(header...)
	return t
}

func (t *table) row(cells ...string) {
	for i, c := range cells {
		cells[i] = safeText(c)
	}
	fmt.Fprintln(t.tw, strings.Join(cells, "\t"))
}

func (t *table) flush() error { return t.tw.Flush() }

// csvOut writes rows with formula guarding.
type csvOut struct {
	w   *csv.Writer
	raw bool
}

func newCSV(w io.Writer, raw bool, header ...string) *csvOut {
	c := &csvOut{w: csv.NewWriter(w), raw: raw}
	_ = c.w.Write(header)
	return c
}

func (c *csvOut) row(cells ...string) {
	for i, s := range cells {
		cells[i] = csvSafe(s, c.raw)
	}
	_ = c.w.Write(cells)
}

func (c *csvOut) flush() error {
	c.w.Flush()
	return c.w.Error()
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func writeJSONLine(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
