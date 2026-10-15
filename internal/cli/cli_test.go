package cli

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"eyalsec.com/cli/api"
)

// fakeAPI is a minimal EyalSec API for the commands to talk to.
type fakeAPI struct {
	t       *testing.T
	queries []api.EventQuery
	pages   map[string]string // events query: cursor -> body
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") != "es2_GOODKEY" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"invalid or expired API key"}`)
		return
	}
	switch r.URL.Path {
	case "/api/account/":
		io.WriteString(w, `{"username":"alice","email":"a@example.com","machine_limit":5,"event_limit":5000,"event_limit_monthly":true,"grant_raise":false}`)
	case "/api/get_all_machines/":
		io.WriteString(w, `{"machines":[["2026-07-01T00:00:00Z","web-01","installed","pid","ubuntu_24_04_x86_64","b1","b2","3.13",false,false,false,false,"python"]]}`)
	case "/api/get_all_events_with_count/":
		var q api.EventQuery
		json.NewDecoder(r.Body).Decode(&q)
		f.queries = append(f.queries, q)
		body, ok := f.pages[q.Cursor]
		if !ok {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"bad cursor"}`)
			return
		}
		io.WriteString(w, body)
	case "/api/event/7":
		io.WriteString(w, `{"trace":"line1\nline2 \u001b[2J","origin":"socket recv","runs":[{"run_uid":"r1","cmdline":"es-python app.py","count":2,"first_seen":"a","last_seen":"b"}]}`)
	case "/api/events_export":
		if r.URL.Query().Get("format") == "csv" {
			io.WriteString(w, "id,sink\n1,open\nTRUNCATED at 50000 rows\n")
			return
		}
		io.WriteString(w, `{"count":1,"events":[],"truncated": true}`)
	case "/api/runs/":
		io.WriteString(w, `{"runs":[{"run_uid":"r1","cmdline":"es-python app.py","first_seen":"a","last_seen":"b","events":1,"occurrences":2}],"next_before":""}`)
	case "/api/get_event_stats/":
		io.WriteString(w, `{"total_hits":3,"unique_types":1,"top_events":[{"where":"open","count":3}]}`)
	case "/api/event_view_counts/":
		io.WriteString(w, `{"python":3}`)
	case "/api/event_count/":
		io.WriteString(w, `{"count":3,"view":"python","event_limit":5000,"event_limit_monthly":true}`)
	case "/api/event_names/":
		io.WriteString(w, `{"names":["open","os system"]}`)
	default:
		w.WriteHeader(404)
	}
}

func evRow(id int, value string) string {
	v, _ := json.Marshal(value)
	b, _ := json.Marshal(id)
	return `["2026-07-05T12:00:00Z","os system",` + string(v) + `,2,"web-01","high","python",` + string(b) +
		`,"","",false,"",[{"label":"command injection","sev":"critical"}],[],false,"",""]`
}

type run struct {
	code           int
	stdout, stderr string
}

func setup(t *testing.T) (*fakeAPI, func(stdin string, env map[string]string, args ...string) run) {
	t.Helper()
	f := &fakeAPI{t: t, pages: map[string]string{
		"":   `{"events":[` + evRow(1, "a") + `],"next_cursor":"c1"}`,
		"c1": `{"events":[],"next_cursor":"c2"}`,
		"c2": `{"events":[` + evRow(2, "b") + `,` + evRow(3, "c") + `],"next_cursor":""}`,
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	return f, func(stdin string, env map[string]string, args ...string) run {
		base := map[string]string{
			"EYALSEC_URL":     srv.URL,
			"EYALSEC_API_KEY": "es2_GOODKEY",
			"EYALSEC_CONFIG":  filepath.Join(dir, "config"),
		}
		for k, v := range env {
			base[k] = v
		}
		var out, errb bytes.Buffer
		app := &App{
			Stdin:  strings.NewReader(stdin),
			Stdout: &out,
			Stderr: &errb,
			Env:    func(k string) string { return base[k] },
		}
		code := app.Run(context.Background(), args)
		return run{code, out.String(), errb.String()}
	}
}

func TestWhoami(t *testing.T) {
	_, cli := setup(t)
	r := cli("", nil, "whoami")
	if r.code != 0 || !strings.Contains(r.stdout, "alice") || !strings.Contains(r.stdout, "5000 per month per product") {
		t.Fatalf("%+v", r)
	}
	r = cli("", nil, "whoami", "-o", "json")
	var a api.Account
	if err := json.Unmarshal([]byte(r.stdout), &a); err != nil || a.Username != "alice" {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestNoKeyAndBadKey(t *testing.T) {
	_, cli := setup(t)
	r := cli("", map[string]string{"EYALSEC_API_KEY": ""}, "whoami")
	if r.code != 1 || !strings.Contains(r.stderr, "Settings > API access") {
		t.Fatalf("%+v", r)
	}
	r = cli("", map[string]string{"EYALSEC_API_KEY": "es2_WRONG"}, "machines", "list")
	if r.code != 1 || !strings.Contains(r.stderr, "not accepted") {
		t.Fatalf("%+v", r)
	}
}

func TestUsageErrors(t *testing.T) {
	_, cli := setup(t)
	for _, args := range [][]string{
		{"frobnicate"}, {"events"}, {"events", "nope"}, {"events", "get"}, {"events", "get", "x"},
		{"events", "list", "-o", "xml"}, {"events", "list", "--bogus"}, {"events", "search"},
		{"events", "list", "--cond", "value:like:x"}, {"events", "list", "stray"},
		{"events", "export", "--format", "xml"}, {"config", "set-key", "es2_ONARGV"},
	} {
		if r := cli("", nil, args...); r.code != 2 {
			t.Errorf("%v: exit %d, want 2 (%s)", args, r.code, r.stderr)
		}
	}
	if r := cli("", nil, "-h"); r.code != 0 || !strings.Contains(r.stdout, "events export") {
		t.Errorf("-h: %+v", r)
	}
	if r := cli("", nil, "version"); r.code != 0 || !strings.HasPrefix(r.stdout, "eyalsec-cli ") {
		t.Errorf("version: %+v", r)
	}
}

func TestMachinesList(t *testing.T) {
	_, cli := setup(t)
	r := cli("", nil, "machines", "list")
	if r.code != 0 || !strings.Contains(r.stdout, "web-01") || !strings.Contains(r.stdout, "update available") {
		t.Fatalf("%+v", r)
	}
	r = cli("", nil, "machines", "list", "-o", "csv")
	recs, err := csv.NewReader(strings.NewReader(r.stdout)).ReadAll()
	if err != nil || len(recs) != 2 || recs[1][0] != "web-01" || recs[1][7] != "true" {
		t.Fatalf("%v %v", recs, err)
	}
}

func TestEventsList_followsEveryPage(t *testing.T) {
	f, cli := setup(t)
	r := cli("", nil, "events", "list", "-o", "jsonl", "--severity", "high,critical", "--limit", "0")
	if r.code != 0 {
		t.Fatalf("%+v", r)
	}
	lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 events across 3 pages (one empty), got %d: %s", len(lines), r.stdout)
	}
	if len(f.queries) != 3 || f.queries[2].Cursor != "c2" || len(f.queries[2].Severity) != 2 {
		t.Fatalf("queries: %+v", f.queries)
	}
	var e map[string]any
	json.Unmarshal([]byte(lines[0]), &e)
	if e["where"] != "os system" || e["str_repr"] != "a" || e["machine_name"] != "web-01" {
		t.Fatalf("JSON uses the documented field names: %v", e)
	}
}

func TestEventsList_limitStopsEarly(t *testing.T) {
	f, cli := setup(t)
	r := cli("", nil, "events", "list", "--limit", "1")
	if r.code != 0 || !strings.Contains(r.stderr, "Stopped after 1 event;") {
		t.Fatalf("%+v", r)
	}
	if len(f.queries) != 1 {
		t.Fatalf("a limit reached on page 1 must not fetch page 2: %d queries", len(f.queries))
	}
	r = cli("", nil, "events", "list", "-o", "json")
	var evs []api.Event
	if err := json.Unmarshal([]byte(r.stdout), &evs); err != nil || len(evs) != 3 {
		t.Fatalf("%v %d", err, len(evs))
	}
}

func TestEventsList_filtersBecomeTheBody(t *testing.T) {
	f, cli := setup(t)
	f.pages[""] = `{"events":[],"next_cursor":""}`
	r := cli("", nil, "events", "list", "--view", "python", "--from", "2026-06-01", "--to", "2026-06-30",
		"--machine", "web-01", "--source", "socket", "--source", "file", "--tag", "sqli", "--label", "4,5",
		"--where", "^os", "--exclude", "open", "--sort", "severity", "--bucket", "all",
		"--cond", "trace:contains:views.py", "--cond", "sink:!regex:^a:b$", "--any", "--run", "9f2c",
		"--scope", "/srv", "--scope-mode", "is")
	if r.code != 0 {
		t.Fatalf("%+v", r)
	}
	q := f.queries[0]
	if q.View != "python" || q.From != "2026-06-01" || q.To != "2026-06-30" || q.Machine != "web-01" ||
		len(q.Sources) != 2 || q.Tags[0] != "sqli" || q.Labels[1] != 5 || q.WhitelistRepr != "^os" ||
		q.BlacklistRepr != "open" || q.Sort != "severity" || q.Bucket != "all" {
		t.Fatalf("%+v", q)
	}
	if q.Advanced == nil || q.Advanced.Match != "any" || len(q.Advanced.Conditions) != 3 {
		t.Fatalf("advanced: %+v", q.Advanced)
	}
	c := q.Advanced.Conditions[1]
	if c.Field != "sink" || c.Op != "regex" || !c.Negate || c.Value != "^a:b$" {
		t.Fatalf("negated condition with a colon in its value: %+v", c)
	}
	if q.Advanced.Conditions[2] != (api.Condition{Field: "run", Op: "is", Value: "9f2c"}) {
		t.Fatalf("--run: %+v", q.Advanced.Conditions[2])
	}
	if q.Scope == nil || q.Scope.Mode != "is" || q.Scope.Value != "/srv" {
		t.Fatalf("scope: %+v", q.Scope)
	}
	if !strings.Contains(r.stderr, "No events match") {
		t.Fatalf("an empty result should say so: %q", r.stderr)
	}
}

func TestEventsSearch(t *testing.T) {
	f, cli := setup(t)
	// Flags after the positional TEXT must still parse.
	r := cli("", nil, "events", "search", "etc/passwd", "--view", "browser", "-o", "json")
	if r.code != 0 {
		t.Fatalf("%+v", r)
	}
	c := f.queries[0].Advanced.Conditions[0]
	if c.Field != "payload" || c.Op != "contains" || c.Value != "etc/passwd" || f.queries[0].View != "browser" {
		t.Fatalf("%+v", f.queries[0])
	}
	f.queries = nil
	cli("", nil, "events", "search", "--regex", "--field", "trace", "views\\.py")
	c = f.queries[0].Advanced.Conditions[0]
	if c.Field != "trace" || c.Op != "regex" || f.queries[0].Advanced.Match != "all" {
		t.Fatalf("%+v", f.queries[0])
	}
}

func TestTableEscapesHostileValues(t *testing.T) {
	f, cli := setup(t)
	hostile := "x\x1b]0;pwned\x07\x1b[2J\u202eevil\r\nnext"
	f.pages[""] = `{"events":[` + evRow(9, hostile) + `],"next_cursor":""}`
	r := cli("", nil, "events", "list")
	if strings.ContainsAny(r.stdout, "\x1b\x07\r") || strings.Contains(r.stdout, "\u202e") {
		t.Fatalf("raw control characters reached the terminal: %q", r.stdout)
	}
	if !strings.Contains(r.stdout, `\x1b]0;pwned`) || !strings.Contains(r.stdout, `\u202e`) {
		t.Fatalf("escaped form missing: %q", r.stdout)
	}
	// JSON output is data for a program: it keeps the value exactly.
	r = cli("", nil, "events", "list", "-o", "jsonl")
	var e api.Event
	if err := json.Unmarshal([]byte(r.stdout), &e); err != nil || e.Value != hostile {
		t.Fatalf("jsonl must round-trip the value: %v %q", err, e.Value)
	}
}

func TestCSVFormulaGuard(t *testing.T) {
	f, cli := setup(t)
	f.pages[""] = `{"events":[` + evRow(9, "=HYPERLINK(\"http://x\")") + `],"next_cursor":""}`
	r := cli("", nil, "events", "list", "-o", "csv")
	recs, _ := csv.NewReader(strings.NewReader(r.stdout)).ReadAll()
	if recs[1][6] != `'=HYPERLINK("http://x")` {
		t.Fatalf("formula not guarded: %q", recs[1][6])
	}
	r = cli("", nil, "events", "list", "-o", "csv", "--raw-csv")
	recs, _ = csv.NewReader(strings.NewReader(r.stdout)).ReadAll()
	if recs[1][6] != `=HYPERLINK("http://x")` {
		t.Fatalf("--raw-csv must keep the value: %q", recs[1][6])
	}
}

func TestEventsGet(t *testing.T) {
	_, cli := setup(t)
	r := cli("", nil, "events", "get", "7")
	if r.code != 0 || !strings.Contains(r.stdout, "line1\nline2") || strings.Contains(r.stdout, "\x1b") ||
		!strings.Contains(r.stdout, "es-python app.py") {
		t.Fatalf("%+v", r)
	}
	r = cli("", nil, "events", "get", "8")
	if r.code != 1 || !strings.Contains(r.stderr, "404") {
		t.Fatalf("%+v", r)
	}
}

func TestEventsExport(t *testing.T) {
	_, cli := setup(t)
	out := filepath.Join(t.TempDir(), "events.csv")
	r := cli("", nil, "events", "export", "-O", out, "--view", "python")
	if r.code != 0 || !strings.Contains(r.stderr, "50,000") {
		t.Fatalf("%+v", r)
	}
	b, err := os.ReadFile(out)
	if err != nil || !strings.HasPrefix(string(b), "id,sink") {
		t.Fatalf("%v %q", err, b)
	}
	if _, err := os.Stat(out + ".partial"); !os.IsNotExist(err) {
		t.Fatal("the .partial file must be renamed away")
	}
	r = cli("", nil, "events", "export", "--format", "json")
	if r.code != 0 || !strings.Contains(r.stdout, `"truncated": true`) || !strings.Contains(r.stderr, "50,000") {
		t.Fatalf("%+v", r)
	}
}

func TestStatsCountNamesRuns(t *testing.T) {
	_, cli := setup(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"events", "stats"}, "Total hits"},
		{[]string{"events", "count"}, "es-python  3"},
		{[]string{"events", "count", "--view", "python"}, "3 events counted toward a quota of 5000 this month"},
		{[]string{"events", "names"}, "os system"},
		{[]string{"runs", "list"}, "es-python app.py"},
		{[]string{"runs", "list", "-o", "csv"}, "r1,a,b,1,2,es-python app.py"},
	} {
		r := cli("", nil, tc.args...)
		if r.code != 0 || !strings.Contains(r.stdout, tc.want) {
			t.Errorf("%v: %+v", tc.args, r)
		}
	}
}

func TestConfigSetKeyAndPrecedence(t *testing.T) {
	_, cli := setup(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sub", "config")
	env := map[string]string{"EYALSEC_API_KEY": "", "EYALSEC_CONFIG": cfg}

	// A wrong key is verified and refused, and nothing is written.
	r := cli("es2_WRONG\n", env, "config", "set-key")
	if r.code != 1 {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(cfg); !os.IsNotExist(err) {
		t.Fatal("a refused key must not be saved")
	}

	r = cli("es2_GOODKEY\n", env, "config", "set-key")
	if r.code != 0 || !strings.Contains(r.stderr, "belongs to alice") {
		t.Fatalf("%+v", r)
	}
	st, err := os.Stat(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v, want 0600", st.Mode().Perm())
	}
	// The saved key now works with no environment key.
	if r := cli("", env, "whoami"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	// The environment wins over the file.
	env2 := map[string]string{"EYALSEC_API_KEY": "es2_WRONG", "EYALSEC_CONFIG": cfg}
	if r := cli("", env2, "whoami"); r.code != 1 {
		t.Fatalf("EYALSEC_API_KEY must take precedence: %+v", r)
	}
	r = cli("", env, "config", "show")
	if !strings.Contains(r.stdout, "*****") || strings.Contains(r.stdout, "es2_GOODKEY") {
		t.Fatalf("config show must mask the key: %q", r.stdout)
	}
	if r := cli("", env, "config", "path"); strings.TrimSpace(r.stdout) != cfg {
		t.Fatalf("%+v", r)
	}
}

func TestConfigSetURL(t *testing.T) {
	_, cli := setup(t)
	cfg := filepath.Join(t.TempDir(), "config")
	env := map[string]string{"EYALSEC_CONFIG": cfg, "EYALSEC_URL": ""}
	if r := cli("", env, "config", "set-url", "http://eyalsec.com"); r.code != 2 {
		t.Fatalf("plain http to a remote host must be refused: %+v", r)
	}
	if r := cli("", env, "config", "set-url", "https://example.test/"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	vals, err := readConfigFile(cfg)
	if err != nil || vals["url"] != "https://example.test" {
		t.Fatalf("%v %v", vals, err)
	}
	if r := cli("", env, "config", "show"); !strings.Contains(r.stdout, "https://example.test") {
		t.Fatalf("%+v", r)
	}
}

func TestReadConfigFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c")
	os.WriteFile(p, []byte("# comment\n\napi_key = \"es2_X\"\nurl=https://e.test\n"), 0o600)
	v, err := readConfigFile(p)
	if err != nil || v["api_key"] != "es2_X" || v["url"] != "https://e.test" {
		t.Fatalf("%v %v", v, err)
	}
	os.WriteFile(p, []byte("token = x\n"), 0o600)
	if _, err := readConfigFile(p); err == nil {
		t.Fatal("unknown keys must be refused")
	}
	if v, err := readConfigFile(filepath.Join(t.TempDir(), "missing")); err != nil || len(v) != 0 {
		t.Fatal("a missing file is an empty config")
	}
}

func TestDefaultConfigPath(t *testing.T) {
	env := map[string]string{"HOME": "/home/a", "XDG_CONFIG_HOME": "", "AppData": `C:\Users\a\AppData\Roaming`}
	get := func(k string) string { return env[k] }
	p, err := defaultConfigPath(get)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(filepath.ToSlash(p), "eyalsec/config") {
		t.Fatalf("%q", p)
	}
	env["EYALSEC_CONFIG"] = "/x/y"
	if p, _ := defaultConfigPath(get); p != "/x/y" {
		t.Fatalf("EYALSEC_CONFIG must win: %q", p)
	}
}

func TestSafeText(t *testing.T) {
	cases := map[string]string{
		"plain":            "plain",
		"a\nb":             `a\nb`,
		"\x1b[31m":         `\x1b[31m`,
		"\u202eabc":        `\u202eabc`,
		"caf\xe9":          `caf\xe9`,
		"emoji \U0001F600": "emoji \U0001F600",
		"\x9b":             `\x9b`,
		"\u009b":           `\x9b`,
	}
	for in, want := range cases {
		if got := safeText(in); got != want {
			t.Errorf("safeText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseInterspersed(t *testing.T) {
	var c common
	var out string
	fs := newFlagSet(&App{Stderr: io.Discard}, "x", "x")
	c.register(fs)
	fs.StringVar(&out, "o", "", "")
	pos, err := parseInterspersed(fs, []string{"a", "-o", "json", "b", "--", "-c"})
	if err != nil || out != "json" || strings.Join(pos, ",") != "a,b,-c" {
		t.Fatalf("pos=%v out=%q err=%v", pos, out, err)
	}
}

func TestExplain(t *testing.T) {
	if s := explain(&api.Error{Status: 400, Message: "invalid whitelist_repr"}); !strings.Contains(s, "--where") {
		t.Fatalf("%q", s)
	}
	if s := explain(&api.Error{Status: 503}); !strings.Contains(s, "try again") {
		t.Fatalf("%q", s)
	}
}
