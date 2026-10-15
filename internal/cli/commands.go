package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"eyalsec.com/cli/api"
)

// ---------------------------------------------------------------- whoami

func (a *App) cmdWhoami(ctx context.Context, args []string) error {
	var c common
	var out string
	fs := newFlagSet(a, "whoami", "whoami [-o text|json]")
	c.register(fs)
	fs.StringVar(&out, "o", "text", "output: text or json")
	if _, err := parseInterspersed(fs, args); err != nil {
		return flagErr(err)
	}
	cl, err := a.client(&c)
	if err != nil {
		return err
	}
	acc, err := cl.Account(ctx)
	if err != nil {
		return err
	}
	switch out {
	case "json":
		return writeJSON(a.Stdout, acc)
	case "text":
	default:
		return usagef("-o must be text or json, not %q", out)
	}
	limit := func(n int) string {
		if n < 0 {
			return "no limit"
		}
		return strconv.Itoa(n)
	}
	period := ""
	if acc.EventLimitMonthly {
		period = " per month"
	}
	t := newTable(a.Stdout, "Account", acc.Username)
	t.row("Address", cl.BaseURL)
	if acc.Email != "" {
		t.row("Email", acc.Email)
	}
	t.row("Machines allowed", limit(acc.MachineLimit)+" per product")
	t.row("Event quota", limit(acc.EventLimit)+period+" per product")
	t.row("Raise rules", onOff(acc.GrantRaise))
	t.row("Two-factor sign-in", onOff(acc.TOTPEnabled || acc.Email2FAEnabled))
	return t.flush()
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// ---------------------------------------------------------------- machines

func (a *App) cmdMachinesList(ctx context.Context, args []string) error {
	var c common
	var out string
	var rawCSV bool
	fs := newFlagSet(a, "machines list", "machines list [-o table|json|csv]")
	c.register(fs)
	fs.StringVar(&out, "o", "table", "output: table, json, jsonl or csv")
	fs.BoolVar(&rawCSV, "raw-csv", false, "do not guard CSV cells against spreadsheet formulas")
	if _, err := parseInterspersed(fs, args); err != nil {
		return flagErr(err)
	}
	if err := checkOutput(out, "table", "json", "jsonl", "csv"); err != nil {
		return err
	}
	cl, err := a.client(&c)
	if err != nil {
		return err
	}
	ms, err := cl.Machines(ctx)
	if err != nil {
		return err
	}
	switch out {
	case "json":
		if ms == nil {
			ms = []api.Machine{}
		}
		return writeJSON(a.Stdout, ms)
	case "jsonl":
		for _, m := range ms {
			if err := writeJSONLine(a.Stdout, m); err != nil {
				return err
			}
		}
		return nil
	case "csv":
		w := newCSV(a.Stdout, rawCSV, "machine_name", "product", "status", "os_type", "python_version",
			"installed_build", "current_build", "update_available", "public_id", "created_at")
		for _, m := range ms {
			w.row(m.Name, m.AgentKind, m.Status, m.OSType, m.PythonVersion, m.InstalledBuild,
				m.CurrentBuild, strconv.FormatBool(m.UpdateAvailable()), m.PublicID, fmtTime(m.CreatedAt))
		}
		return w.flush()
	}
	if len(ms) == 0 {
		fmt.Fprintln(a.Stderr, "No machines yet. Add one on the Machines page of your dashboard.")
		return nil
	}
	t := newTable(a.Stdout, "NAME", "PRODUCT", "STATUS", "OS", "PYTHON", "BUILD", "NOTE")
	for _, m := range ms {
		var notes []string
		if m.UpdateAvailable() {
			notes = append(notes, "update available")
		}
		if m.CloneLocked {
			notes = append(notes, "copy seen elsewhere")
		}
		if m.Stalled {
			notes = append(notes, "install stalled")
		}
		if m.StaleAgent {
			notes = append(notes, "old copy still reporting")
		}
		py := m.PythonVersion
		if m.AgentKind != "python" {
			py = ""
		}
		t.row(m.Name, productName(m.AgentKind), m.Status, dash(m.OSType), dash(py), dash(m.InstalledBuild), strings.Join(notes, ", "))
	}
	return t.flush()
}

func productName(kind string) string {
	switch kind {
	case "python":
		return "es-python"
	case "browser":
		return "es-chromium"
	case "":
		return "-"
	}
	return "es-" + kind
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func checkOutput(out string, allowed ...string) error {
	for _, a := range allowed {
		if out == a {
			return nil
		}
	}
	return usagef("-o must be one of %s, not %q", strings.Join(allowed, ", "), out)
}

// ---------------------------------------------------------------- event filters

// listFlag collects a repeatable, comma-separated flag.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error {
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

// condFlag collects --cond field:op[:value] conditions.
type condFlag []api.Condition

func (c *condFlag) String() string { return "" }
func (c *condFlag) Set(s string) error {
	cond, err := parseCondition(s)
	if err != nil {
		return err
	}
	*c = append(*c, cond)
	return nil
}

var conditionOps = map[string]bool{
	"contains": true, "ncontains": true, "is": true, "nis": true, "starts": true,
	"ends": true, "regex": true, "nregex": true, "empty": true, "nempty": true,
}

// parseCondition reads field:op[:value]. A "!" before the operator negates it
// (value:!contains:test). The value may itself contain colons.
func parseCondition(s string) (api.Condition, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 2 || parts[0] == "" {
		return api.Condition{}, fmt.Errorf("condition %q: use field:op:value, for example value:contains:passwd", s)
	}
	c := api.Condition{Field: strings.TrimSpace(parts[0]), Op: strings.TrimSpace(parts[1])}
	if strings.HasPrefix(c.Op, "!") {
		c.Negate, c.Op = true, c.Op[1:]
	}
	if !conditionOps[c.Op] {
		return api.Condition{}, fmt.Errorf("condition %q: unknown operator %q (contains, ncontains, is, nis, starts, ends, regex, nregex, empty, nempty)", s, c.Op)
	}
	if len(parts) == 3 {
		c.Value = parts[2]
	}
	if c.Value == "" && c.Op != "empty" && c.Op != "nempty" {
		return api.Condition{}, fmt.Errorf("condition %q: operator %q needs a value", s, c.Op)
	}
	return c, nil
}

// eventFilters is the flag form of api.EventQuery.
type eventFilters struct {
	view, bucket, from, to, machine, where, exclude, sort string
	severity, sources, tags, labels                       listFlag
	conds                                                 condFlag
	anyMatch, xssOnly, scopeEmpty                         bool
	run, scope, scopeMode                                 string
}

func (f *eventFilters) register(fs *flag.FlagSet) {
	fs.StringVar(&f.view, "view", "", "product: python or browser (default: every product on your account)")
	fs.StringVar(&f.bucket, "bucket", "", "live (default), suppressed or all")
	fs.StringVar(&f.from, "from", "", "first day, YYYY-MM-DD or RFC3339")
	fs.StringVar(&f.to, "to", "", "last day, inclusive")
	fs.StringVar(&f.machine, "machine", "", "one machine, by its exact name")
	fs.Var(&f.severity, "severity", "severities to keep, comma-separated: critical,high,medium,low,info")
	fs.Var(&f.sources, "source", "taint sources to keep: socket,file,stdin,env,argv,manual,fuzzer,foreign")
	fs.Var(&f.tags, "tag", "impact classes to keep, such as sqli,xss")
	fs.Var(&f.labels, "label", "label ids to keep, comma-separated")
	fs.StringVar(&f.where, "where", "", "regex: keep events whose event name (sink) matches")
	fs.StringVar(&f.exclude, "exclude", "", "regex: drop events whose event name (sink) matches")
	fs.StringVar(&f.sort, "sort", "", "newest (default) or severity")
	fs.Var(&f.conds, "cond", "condition field:op:value, repeatable (e.g. trace:contains:views.py, sink:!regex:^open$)")
	fs.BoolVar(&f.anyMatch, "any", false, "keep events matching any --cond (default: all)")
	fs.StringVar(&f.run, "run", "", "only events from one run id (es-python)")
	fs.StringVar(&f.scope, "scope", "", "scope value: a page host (es-chromium) or the start of the origin (es-python)")
	fs.StringVar(&f.scopeMode, "scope-mode", "ends", "how --scope matches: is, ends or regex")
	fs.BoolVar(&f.scopeEmpty, "scope-empty", false, "with --scope, also keep events that have no scope")
	fs.BoolVar(&f.xssOnly, "xss-only", false, "es-chromium: only sinks that can run script (needs --view browser)")
}

func (f *eventFilters) query() (api.EventQuery, error) {
	q := api.EventQuery{
		View: f.view, Bucket: f.bucket, From: f.from, To: f.to, Machine: f.machine,
		WhitelistRepr: f.where, BlacklistRepr: f.exclude, Sort: f.sort,
		Severity: f.severity, Sources: f.sources, Tags: f.tags, XSSOnly: f.xssOnly,
	}
	for _, s := range f.labels {
		n, err := strconv.Atoi(s)
		if err != nil {
			return q, usagef("--label takes label ids (numbers), not %q", s)
		}
		q.Labels = append(q.Labels, n)
	}
	conds := append([]api.Condition(nil), f.conds...)
	if f.run != "" {
		conds = append(conds, api.Condition{Field: "run", Op: "is", Value: f.run})
	}
	if len(conds) > 0 {
		match := "all"
		if f.anyMatch {
			match = "any"
		}
		q.Advanced = &api.Advanced{Match: match, Conditions: conds}
	}
	if f.scope != "" {
		q.Scope = &api.Scope{Mode: f.scopeMode, Value: f.scope, IncludeEmpty: f.scopeEmpty}
	}
	return q, nil
}

// ---------------------------------------------------------------- events list / search

type listOpts struct {
	out      string
	limit    int
	progress bool
	rawCSV   bool
	wide     bool
}

func (o *listOpts) register(fs *flag.FlagSet) {
	fs.StringVar(&o.out, "o", "table", "output: table, json, jsonl or csv")
	fs.IntVar(&o.limit, "limit", 100, "stop after this many events; 0 means every matching event")
	fs.BoolVar(&o.progress, "progress", false, "report paging progress on standard error")
	fs.BoolVar(&o.rawCSV, "raw-csv", false, "do not guard CSV cells against spreadsheet formulas")
	fs.BoolVar(&o.wide, "wide", false, "table: do not shorten long values")
}

func (a *App) cmdEventsList(ctx context.Context, args []string) error {
	var c common
	var f eventFilters
	var o listOpts
	fs := newFlagSet(a, "events list", "events list [filters] [-o table|json|jsonl|csv] [--limit N]")
	c.register(fs)
	f.register(fs)
	o.register(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return flagErr(err)
	}
	if len(pos) > 0 {
		return usagef("events list takes no arguments (got %q); to search text use: eyalsec-cli events search TEXT", pos[0])
	}
	q, err := f.query()
	if err != nil {
		return err
	}
	return a.listEvents(ctx, &c, q, o)
}

func (a *App) cmdEventsSearch(ctx context.Context, args []string) error {
	var c common
	var f eventFilters
	var o listOpts
	var field string
	var regex bool
	fs := newFlagSet(a, "events search", "events search TEXT [--field value|payload|trace|origin|sink|...] [--regex] [filters]")
	c.register(fs)
	f.register(fs)
	o.register(fs)
	fs.StringVar(&field, "field", "", "field to search (default: value for es-python, payload for es-chromium)")
	fs.BoolVar(&regex, "regex", false, "treat TEXT as a regular expression")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return flagErr(err)
	}
	if len(pos) != 1 || pos[0] == "" {
		return usagef("events search needs exactly one TEXT to look for (quote it if it has spaces)")
	}
	if field == "" {
		field = "value"
		if f.view == "browser" {
			field = "payload"
		}
	}
	op := "contains"
	if regex {
		op = "regex"
	}
	f.conds = append(condFlag{{Field: field, Op: op, Value: pos[0]}}, f.conds...)
	if f.anyMatch && len(f.conds) > 1 {
		return usagef("--any cannot be combined with search TEXT; use events list with --cond and --any")
	}
	q, err := f.query()
	if err != nil {
		return err
	}
	return a.listEvents(ctx, &c, q, o)
}

func (a *App) listEvents(ctx context.Context, c *common, q api.EventQuery, o listOpts) error {
	if err := checkOutput(o.out, "table", "json", "jsonl", "csv"); err != nil {
		return err
	}
	if o.limit < 0 {
		return usagef("--limit cannot be negative")
	}
	cl, err := a.client(c)
	if err != nil {
		return err
	}

	var (
		tbl     *table
		cw      *csvOut
		jsonAll []api.Event
		n       int
		more    bool
		hidden  *api.HiddenBy
	)
	switch o.out {
	case "table":
		tbl = newTable(a.Stdout, "ID", "SEEN", "SEVERITY", "MACHINE", "EVENT", "VALUE", "COUNT")
	case "csv":
		cw = newCSV(a.Stdout, o.rawCSV, "id", "created_at", "severity", "agent_kind", "machine", "sink",
			"value", "count", "source_label", "taint_source", "context", "suppressed", "sanitize_reason",
			"impact", "labels", "has_comment", "extension")
	case "json":
		jsonAll = []api.Event{}
	}
	valueWidth := 60
	if o.wide {
		valueWidth = 0
	}
	var pageLen, pageIdx int
	var pageNext string
	emit := func(e api.Event) error {
		n++
		pageIdx++
		switch o.out {
		case "table":
			tbl.row(strconv.FormatInt(e.ID, 10), e.CreatedAt.Local().Format("2006-01-02 15:04"), e.Severity,
				e.Machine, e.Where, truncate(safeText(e.Value), valueWidth), strconv.FormatInt(e.Count, 10))
		case "csv":
			var imp, labels []string
			for _, i := range e.Impact {
				imp = append(imp, i.Label+":"+i.Severity)
			}
			for _, l := range e.Labels {
				labels = append(labels, l.Name)
			}
			cw.row(strconv.FormatInt(e.ID, 10), fmtTime(e.CreatedAt), e.Severity, e.AgentKind, e.Machine,
				e.Where, e.Value, strconv.FormatInt(e.Count, 10), e.SourceLabel, e.TaintSource, e.Context,
				strconv.FormatBool(e.Suppressed), e.SanitizeReason, strings.Join(imp, ";"),
				strings.Join(labels, ";"), strconv.FormatBool(e.HasComment), e.Extension)
		case "jsonl":
			return writeJSONLine(a.Stdout, e)
		case "json":
			jsonAll = append(jsonAll, e)
		}
		if o.limit > 0 && n >= o.limit {
			// Stop without fetching another page; there may be more when
			// this page has events left or the cursor goes on.
			more = pageIdx < pageLen || pageNext != ""
			return api.ErrStop
		}
		return nil
	}
	progress := func(p api.PageProgress) {
		pageLen, pageIdx, pageNext = p.PageEvents, 0, p.NextCursor
		hidden = p.HiddenBy
		if o.progress {
			fmt.Fprintf(a.Stderr, "page %d: %d events so far, %d rows examined, reached %s\n",
				p.Pages, n, p.Scanned, p.OldestExamined)
		}
	}
	walkErr := cl.EachEvent(ctx, q, emit, progress)

	if walkErr != nil && n == 0 {
		return walkErr
	}
	// Write what we have even when the walk failed part-way, then report.
	var flushErr error
	switch o.out {
	case "table":
		flushErr = tbl.flush()
	case "csv":
		flushErr = cw.flush()
	case "json":
		flushErr = writeJSON(a.Stdout, jsonAll)
	}
	if walkErr != nil {
		return walkErr
	}
	if flushErr != nil {
		return flushErr
	}
	if hidden != nil {
		fmt.Fprintf(a.Stderr, "Every event in this view is hidden by your Hide rule %q (id %d). Turn it off or narrow its pattern to see events again.\n", hidden.Label, hidden.ID)
	} else if n == 0 && o.out == "table" {
		fmt.Fprintln(a.Stderr, "No events match.")
	}
	if more {
		fmt.Fprintf(a.Stderr, "Stopped after %s; more may match. Use --limit 0 for all of them, or: eyalsec-cli events export\n", plural(o.limit, "event"))
	}
	return nil
}

// ---------------------------------------------------------------- events get

func (a *App) cmdEventsGet(ctx context.Context, args []string) error {
	var c common
	var out string
	fs := newFlagSet(a, "events get", "events get ID [-o text|json]")
	c.register(fs)
	fs.StringVar(&out, "o", "text", "output: text or json")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return flagErr(err)
	}
	if len(pos) != 1 {
		return usagef("events get needs one event id (the ID column of events list)")
	}
	id, err := strconv.ParseInt(pos[0], 10, 64)
	if err != nil || id <= 0 {
		return usagef("%q is not an event id; ids are positive numbers", pos[0])
	}
	if err := checkOutput(out, "text", "json"); err != nil {
		return err
	}
	cl, err := a.client(&c)
	if err != nil {
		return err
	}
	d, err := cl.Event(ctx, id)
	if err != nil {
		return err
	}
	if out == "json" {
		return writeJSON(a.Stdout, d)
	}
	w := a.Stdout
	section := func(title, body string) {
		if strings.TrimSpace(body) == "" {
			return
		}
		fmt.Fprintf(w, "%s\n%s\n%s\n\n", title, strings.Repeat("-", len(title)), safeBlock(strings.TrimRight(body, "\n")))
	}
	fmt.Fprintf(w, "Event %d\n\n", id)
	section("Where the data came in", d.Origin)
	section("Where the value was created", d.ReprCreated)
	section("Stack trace", d.Trace)
	section("Source code", d.SourceCode)
	section("Sink code", d.SinkCode)
	section("Detail", d.Detail)
	if d.Extension != nil && d.Extension.Label != "" {
		section("Extension", d.Extension.Label)
	}
	if d.RuleSource != "" {
		section("Rule source", d.RuleSource)
	}
	section("Your note", d.Comment)
	if len(d.Runs) > 0 {
		fmt.Fprintf(w, "Runs\n----\n")
		t := newTable(w, "RUN", "COUNT", "FIRST SEEN", "LAST SEEN", "COMMAND")
		for _, r := range d.Runs {
			t.row(dash(r.RunUID), strconv.FormatInt(r.Count, 10), r.FirstSeen, r.LastSeen, r.Cmdline)
		}
		if err := t.flush(); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------- events export

func (a *App) cmdEventsExport(ctx context.Context, args []string) error {
	var c common
	var f eventFilters
	var format, outFile string
	fs := newFlagSet(a, "events export", "events export [--format csv|json] [-O FILE] [filters]")
	c.register(fs)
	f.register(fs)
	fs.StringVar(&format, "format", "csv", "csv or json")
	fs.StringVar(&outFile, "O", "", "write to FILE instead of standard output")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return flagErr(err)
	}
	if len(pos) > 0 {
		return usagef("events export takes no arguments (got %q)", pos[0])
	}
	if format != "csv" && format != "json" {
		return usagef("--format must be csv or json, not %q", format)
	}
	q, err := f.query()
	if err != nil {
		return err
	}
	cl, err := a.client(&c)
	if err != nil {
		return err
	}
	var w io.Writer = a.Stdout
	var file *os.File
	if outFile != "" && outFile != "-" {
		file, err = os.OpenFile(outFile+".partial", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		w = file
	}
	tail := &tailBuffer{max: 4096}
	n, err := cl.Export(ctx, q, format, io.MultiWriter(w, tail))
	if file != nil {
		cerr := file.Close()
		if err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(outFile + ".partial")
			return err
		}
		if err := os.Rename(outFile+".partial", outFile); err != nil {
			return err
		}
		fmt.Fprintf(a.Stderr, "Wrote %s (%d bytes).\n", outFile, n)
	} else if err != nil {
		return err
	}
	if tail.truncated(format) {
		fmt.Fprintln(a.Stderr, "The export stopped at the server's 50,000-row limit. Narrow --from/--to or the filters to get the rest.")
	}
	return nil
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	max int
	b   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = append([]byte(nil), t.b[len(t.b)-t.max:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) truncated(format string) bool {
	if format == "json" {
		compact := bytes.ReplaceAll(t.b, []byte(" "), nil)
		return bytes.Contains(compact, []byte(`"truncated":true`))
	}
	lines := strings.Split(strings.TrimRight(string(t.b), "\r\n"), "\n")
	return strings.HasPrefix(lines[len(lines)-1], "TRUNCATED")
}

// ---------------------------------------------------------------- events stats / count / names

func (a *App) cmdEventsStats(ctx context.Context, args []string) error {
	var c common
	var out string
	fs := newFlagSet(a, "events stats", "events stats [-o text|json]")
	c.register(fs)
	fs.StringVar(&out, "o", "text", "output: text or json")
	if _, err := parseInterspersed(fs, args); err != nil {
		return flagErr(err)
	}
	if err := checkOutput(out, "text", "json"); err != nil {
		return err
	}
	cl, err := a.client(&c)
	if err != nil {
		return err
	}
	s, err := cl.Stats(ctx)
	if err != nil {
		return err
	}
	if out == "json" {
		return writeJSON(a.Stdout, s)
	}
	t := newTable(a.Stdout, "Total hits", strconv.FormatInt(s.TotalHits, 10))
	t.row("Event types", strconv.FormatInt(s.UniqueTypes, 10))
	t.row("Last hour", strconv.FormatInt(s.Last1h, 10))
	t.row("Last 24 hours", strconv.FormatInt(s.Last24h, 10))
	t.row("Last 7 days", strconv.FormatInt(s.Last7d, 10))
	if s.FirstDetection != "" {
		t.row("First detection", s.FirstDetection)
	}
	if s.LatestDetection != "" {
		t.row("Latest detection", s.LatestDetection)
	}
	if err := t.flush(); err != nil {
		return err
	}
	if len(s.TopEvents) > 0 {
		fmt.Fprintln(a.Stdout)
		t := newTable(a.Stdout, "TOP EVENT", "COUNT")
		for _, e := range s.TopEvents {
			t.row(e.Where, strconv.FormatInt(e.Count, 10))
		}
		return t.flush()
	}
	return nil
}

func (a *App) cmdEventsCount(ctx context.Context, args []string) error {
	var c common
	var out, view, bucket string
	fs := newFlagSet(a, "events count", "events count [--view python|browser] [-o text|json]")
	c.register(fs)
	fs.StringVar(&view, "view", "", "one product's quota count (default: the count per product)")
	fs.StringVar(&bucket, "bucket", "", "for the per-product counts: live (default), suppressed or all")
	fs.StringVar(&out, "o", "text", "output: text or json")
	if _, err := parseInterspersed(fs, args); err != nil {
		return flagErr(err)
	}
	if err := checkOutput(out, "text", "json"); err != nil {
		return err
	}
	cl, err := a.client(&c)
	if err != nil {
		return err
	}
	if view != "" {
		n, err := cl.EventCount(ctx, view)
		if err != nil {
			return err
		}
		if out == "json" {
			return writeJSON(a.Stdout, n)
		}
		limit := "no limit"
		if n.EventLimit >= 0 {
			limit = strconv.FormatInt(n.EventLimit, 10)
			if n.EventLimitMonthly {
				limit += " this month"
			}
		}
		fmt.Fprintf(a.Stdout, "%s: %d events counted toward a quota of %s\n", productName(n.View), n.Count, limit)
		return nil
	}
	counts, err := cl.ViewCounts(ctx, bucket)
	if err != nil {
		return err
	}
	if out == "json" {
		return writeJSON(a.Stdout, counts)
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t := newTable(a.Stdout, "PRODUCT", "EVENTS")
	for _, k := range keys {
		t.row(productName(k), strconv.FormatInt(counts[k], 10))
	}
	return t.flush()
}

func (a *App) cmdEventsNames(ctx context.Context, args []string) error {
	var c common
	var out string
	fs := newFlagSet(a, "events names", "events names [-o text|json]")
	c.register(fs)
	fs.StringVar(&out, "o", "text", "output: text or json")
	if _, err := parseInterspersed(fs, args); err != nil {
		return flagErr(err)
	}
	if err := checkOutput(out, "text", "json"); err != nil {
		return err
	}
	cl, err := a.client(&c)
	if err != nil {
		return err
	}
	names, err := cl.EventNames(ctx)
	if err != nil {
		return err
	}
	if out == "json" {
		if names == nil {
			names = []string{}
		}
		return writeJSON(a.Stdout, names)
	}
	for _, n := range names {
		fmt.Fprintln(a.Stdout, safeText(n))
	}
	return nil
}

// ---------------------------------------------------------------- runs

func (a *App) cmdRunsList(ctx context.Context, args []string) error {
	var c common
	var out, machine, q string
	var limit int
	var rawCSV bool
	fs := newFlagSet(a, "runs list", "runs list [--machine NAME] [--q TEXT] [--limit N] [-o table|json|jsonl|csv]")
	c.register(fs)
	fs.StringVar(&machine, "machine", "", "one machine, by name")
	fs.StringVar(&q, "q", "", "a piece of the command line, case-insensitive")
	fs.IntVar(&limit, "limit", 50, "stop after this many runs; 0 means all")
	fs.StringVar(&out, "o", "table", "output: table, json, jsonl or csv")
	fs.BoolVar(&rawCSV, "raw-csv", false, "do not guard CSV cells against spreadsheet formulas")
	if _, err := parseInterspersed(fs, args); err != nil {
		return flagErr(err)
	}
	if err := checkOutput(out, "table", "json", "jsonl", "csv"); err != nil {
		return err
	}
	if limit < 0 {
		return usagef("--limit cannot be negative")
	}
	cl, err := a.client(&c)
	if err != nil {
		return err
	}
	var runs []api.Run
	before := ""
	more := false
	for {
		page := 200
		if limit > 0 && limit-len(runs) < page {
			page = limit - len(runs)
		}
		p, err := cl.Runs(ctx, api.RunsQuery{Machine: machine, Q: q, Before: before, Limit: page})
		if err != nil {
			return err
		}
		runs = append(runs, p.Runs...)
		if p.NextBefore == "" || len(p.Runs) == 0 {
			break
		}
		if limit > 0 && len(runs) >= limit {
			more = true
			break
		}
		before = p.NextBefore
	}
	if limit > 0 && len(runs) > limit {
		runs = runs[:limit]
	}
	switch out {
	case "json":
		if runs == nil {
			runs = []api.Run{}
		}
		return writeJSON(a.Stdout, runs)
	case "jsonl":
		for _, r := range runs {
			if err := writeJSONLine(a.Stdout, r); err != nil {
				return err
			}
		}
		return nil
	case "csv":
		w := newCSV(a.Stdout, rawCSV, "run_uid", "first_seen", "last_seen", "events", "occurrences", "cmdline")
		for _, r := range runs {
			w.row(r.RunUID, r.FirstSeen, r.LastSeen, strconv.FormatInt(r.Events, 10), strconv.FormatInt(r.Occurrences, 10), r.Cmdline)
		}
		return w.flush()
	}
	if len(runs) == 0 {
		fmt.Fprintln(a.Stderr, "No runs match.")
		return nil
	}
	t := newTable(a.Stdout, "RUN", "FIRST SEEN", "EVENTS", "HITS", "COMMAND")
	for _, r := range runs {
		t.row(dash(r.RunUID), r.FirstSeen, strconv.FormatInt(r.Events, 10), strconv.FormatInt(r.Occurrences, 10), truncate(r.Cmdline, 80))
	}
	if err := t.flush(); err != nil {
		return err
	}
	if more {
		fmt.Fprintf(a.Stderr, "Showing the first %s; more exist. Use --limit 0 for all of them.\n", plural(limit, "run"))
	}
	return nil
}

// ---------------------------------------------------------------- config

func (a *App) cmdConfigSetKey(ctx context.Context, args []string) error {
	var c common
	var noVerify bool
	fs := newFlagSet(a, "config set-key", "config set-key [--no-verify]   (reads the key from standard input)")
	c.register(fs)
	fs.BoolVar(&noVerify, "no-verify", false, "save without checking the key against the API")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return flagErr(err)
	}
	if len(pos) > 0 {
		return usagef("config set-key reads the key from standard input, not from the command line, " +
			"so it stays out of your shell history. Run it and paste the key, or pipe it in")
	}
	key, err := a.readSecret("Paste your API key (it starts with es2_) and press Enter: ")
	if err != nil {
		return err
	}
	if key == "" {
		return usagef("no key was given")
	}
	if strings.ContainsAny(key, " \t") {
		return usagef("the key contains spaces; paste only the key itself")
	}
	if !strings.HasPrefix(key, "es2_") {
		fmt.Fprintln(a.Stderr, "eyalsec-cli: note: EyalSec API keys start with es2_; saving it anyway.")
	}
	path, err := a.configPath(&c)
	if err != nil {
		return err
	}
	values, err := readConfigFile(path)
	if err != nil {
		return err
	}
	if c.url != "" {
		u, err := api.ValidateBaseURL(c.url)
		if err != nil {
			return usagef("%v", err)
		}
		values["url"] = u
	}
	if !noVerify {
		base := values["url"]
		if base == "" {
			base = a.Env("EYALSEC_URL")
		}
		cl, err := api.New(base, key)
		if err != nil {
			return err
		}
		if a.HTTP != nil {
			cl.HTTP = a.HTTP
		}
		acc, err := cl.Account(ctx)
		if err != nil {
			return fmt.Errorf("%s (nothing was saved; use --no-verify to save it anyway)", explain(err))
		}
		fmt.Fprintf(a.Stderr, "The key works: it belongs to %s on %s.\n", safeText(acc.Username), cl.BaseURL)
	}
	values["api_key"] = key
	if err := writeConfigFile(path, values); err != nil {
		return err
	}
	fmt.Fprintf(a.Stderr, "Saved to %s (readable only by you).\n", path)
	if a.Env("EYALSEC_API_KEY") != "" {
		fmt.Fprintln(a.Stderr, "Note: EYALSEC_API_KEY is set in this shell and takes precedence over the saved key.")
	}
	return nil
}

// readSecret reads one line from standard input, without echo when it is a
// terminal on a system with stty.
func (a *App) readSecret(prompt string) (string, error) {
	tty := a.StdinIsTerminal()
	if tty {
		fmt.Fprint(a.Stderr, prompt)
		if runtime.GOOS != "windows" {
			if f, ok := a.Stdin.(*os.File); ok {
				if err := stty(f, "-echo"); err == nil {
					defer func() {
						_ = stty(f, "echo")
						fmt.Fprintln(a.Stderr)
					}()
				}
			}
		}
	}
	line, err := bufio.NewReader(a.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func stty(f *os.File, arg string) error {
	cmd := exec.Command("stty", arg)
	cmd.Stdin = f
	return cmd.Run()
}

func (a *App) cmdConfigSetURL(ctx context.Context, args []string) error {
	var c common
	fs := newFlagSet(a, "config set-url", "config set-url URL")
	fs.StringVar(&c.config, "config", "", "config file to write")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return flagErr(err)
	}
	if len(pos) != 1 {
		return usagef("config set-url needs one address, such as https://eyalsec.com")
	}
	u, err := api.ValidateBaseURL(pos[0])
	if err != nil {
		return usagef("%v", err)
	}
	path, err := a.configPath(&c)
	if err != nil {
		return err
	}
	values, err := readConfigFile(path)
	if err != nil {
		return err
	}
	values["url"] = u
	if err := writeConfigFile(path, values); err != nil {
		return err
	}
	fmt.Fprintf(a.Stderr, "Saved %s to %s.\n", u, path)
	return nil
}

func (a *App) cmdConfigShow(ctx context.Context, args []string) error {
	var c common
	fs := newFlagSet(a, "config show", "config show")
	c.register(fs)
	if _, err := parseInterspersed(fs, args); err != nil {
		return flagErr(err)
	}
	path, err := a.configPath(&c)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(a.Env, path, c.url)
	if err != nil {
		return err
	}
	key, keySrc := "(none)", "-"
	if cfg.APIKey != "" {
		key, keySrc = maskKey(cfg.APIKey), cfg.KeySource
	}
	t := newTable(a.Stdout, "SETTING", "VALUE", "FROM")
	t.row("url", cfg.URL, cfg.URLSource)
	t.row("api_key", key, keySrc)
	t.row("config file", path, "")
	return t.flush()
}

func (a *App) cmdConfigPath(ctx context.Context, args []string) error {
	var c common
	fs := newFlagSet(a, "config path", "config path")
	fs.StringVar(&c.config, "config", "", "config file")
	if _, err := parseInterspersed(fs, args); err != nil {
		return flagErr(err)
	}
	path, err := a.configPath(&c)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.Stdout, path)
	return nil
}
