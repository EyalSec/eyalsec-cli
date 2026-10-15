package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const fullRow = `["2026-07-05T12:00:00Z", "socket-recv", "'...'", 3, "web-01", "high", "python", 12345,
  "src", "ctx", true, "This value was not sanitized.",
  [{"label": "data exfiltration", "sev": "medium"}],
  [{"id": 1, "name": "triage", "color": "amber"}], true, "ext", "socket"]`

func TestEventUnmarshal_allFields(t *testing.T) {
	var e Event
	if err := json.Unmarshal([]byte(fullRow), &e); err != nil {
		t.Fatal(err)
	}
	if e.ID != 12345 || e.Where != "socket-recv" || e.Value != "'...'" || e.Count != 3 ||
		e.Machine != "web-01" || e.Severity != "high" || e.AgentKind != "python" ||
		e.SourceLabel != "src" || e.Context != "ctx" || !e.Suppressed || !e.HasComment ||
		e.Extension != "ext" || e.TaintSource != "socket" {
		t.Fatalf("fields decoded wrong: %+v", e)
	}
	if len(e.Impact) != 1 || e.Impact[0].Severity != "medium" || len(e.Labels) != 1 || e.Labels[0].Name != "triage" {
		t.Fatalf("nested fields decoded wrong: %+v", e)
	}
	if !e.CreatedAt.Equal(time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("created_at = %v", e.CreatedAt)
	}
}

func TestEventUnmarshal_shortAndLongRows(t *testing.T) {
	// An older server sends fewer values; a newer one may append more.
	var short Event
	if err := json.Unmarshal([]byte(`["2026-07-05T12:00:00Z","open","x",1]`), &short); err != nil {
		t.Fatal(err)
	}
	if short.Where != "open" || short.Count != 1 || short.ID != 0 {
		t.Fatalf("short row: %+v", short)
	}
	long := strings.TrimSuffix(fullRow, "]") + `, "a future value", 42]`
	var e Event
	if err := json.Unmarshal([]byte(long), &e); err != nil {
		t.Fatalf("a row with extra trailing values must still decode: %v", err)
	}
	if e.TaintSource != "socket" {
		t.Fatalf("long row: %+v", e)
	}
}

func TestEventUnmarshal_nullsAndEmptyTime(t *testing.T) {
	var e Event
	if err := json.Unmarshal([]byte(`["", "open", null, 1, "m", "low", "python", 7, null, null, false, "", null, null]`), &e); err != nil {
		t.Fatal(err)
	}
	if !e.CreatedAt.IsZero() || e.ID != 7 {
		t.Fatalf("%+v", e)
	}
}

func TestMachineUnmarshal(t *testing.T) {
	row := `["2026-07-01T00:00:00Z", "web-01", "installed", "3f6c1a52-8e0b-4d2a-9c1e-5b7d2f0a9e41",
     "ubuntu_24_04_x86_64", "bc0ef13-20260604T120000Z", "bc0ef13-20260605T080000Z",
     "3.13", false, true, false, false, "python"]`
	var m Machine
	if err := json.Unmarshal([]byte(row), &m); err != nil {
		t.Fatal(err)
	}
	if m.Name != "web-01" || m.OSType != "ubuntu_24_04_x86_64" || !m.CloneLocked || m.AgentKind != "python" {
		t.Fatalf("%+v", m)
	}
	if !m.UpdateAvailable() {
		t.Fatal("installed != current build should mean an update is available")
	}
}

func TestValidateBaseURL(t *testing.T) {
	ok := map[string]string{
		"https://eyalsec.com":       "https://eyalsec.com",
		"https://eyalsec.com/":      "https://eyalsec.com",
		" https://test.example/ ":   "https://test.example",
		"http://127.0.0.1:8080":     "http://127.0.0.1:8080",
		"http://localhost:3000/":    "http://localhost:3000",
		"https://example.com/base/": "https://example.com/base",
	}
	for in, want := range ok {
		got, err := ValidateBaseURL(in)
		if err != nil || got != want {
			t.Errorf("ValidateBaseURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"http://eyalsec.com", "eyalsec.com", "ftp://x", "", "https://x/?a=b"} {
		if _, err := ValidateBaseURL(bad); err == nil {
			t.Errorf("ValidateBaseURL(%q) accepted a bad address", bad)
		}
	}
}

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "es2_TESTKEY")
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func TestClient_sendsKeyAndUserAgent(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "es2_TESTKEY" {
			t.Errorf("X-API-Key = %q", r.Header.Get("X-API-Key"))
		}
		if r.URL.Path != "/api/account/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "eyalsec-cli") {
			t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		io.WriteString(w, `{"username":"alice","machine_limit":5,"event_limit":-1}`)
	})
	a, err := c.Account(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.Username != "alice" || a.EventLimit != -1 {
		t.Fatalf("%+v", a)
	}
}

func TestClient_errors(t *testing.T) {
	cases := []struct {
		status int
		ctype  string
		body   string
		want   string
	}{
		{401, "application/json", `{"error":"invalid or expired API key"}`, "invalid or expired API key"},
		{429, "text/plain", "Too Many Requests\n", "Too Many Requests"},
		{500, "text/html", "<html>oops</html>", ""},
	}
	for _, tc := range cases {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", tc.ctype)
			w.WriteHeader(tc.status)
			io.WriteString(w, tc.body)
		})
		c.MaxRetries = 0
		_, err := c.Account(context.Background())
		var e *Error
		if !errors.As(err, &e) || e.Status != tc.status || e.Message != tc.want {
			t.Errorf("status %d: got %#v", tc.status, err)
		}
		if !IsStatus(err, tc.status) {
			t.Errorf("IsStatus(%d) false", tc.status)
		}
	}
}

func TestClient_retries429WithRetryAfter(t *testing.T) {
	calls := 0
	var waited []time.Duration
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(429)
			return
		}
		io.WriteString(w, `{"machines":[]}`)
	})
	c.sleep = func(_ context.Context, d time.Duration) error { waited = append(waited, d); return nil }
	if _, err := c.Machines(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 3 || len(waited) != 2 || waited[0] != 7*time.Second {
		t.Fatalf("calls=%d waited=%v", calls, waited)
	}
}

func TestClient_429GivesUpAfterMaxRetries(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(429)
	})
	c.MaxRetries = 2
	_, err := c.Machines(context.Background())
	if !IsStatus(err, 429) || calls != 3 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestClient_retryResendsBody(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		if !bytes.Contains(b, []byte(`"view":"python"`)) {
			t.Errorf("call %d body = %s", calls, b)
		}
		if calls == 1 {
			w.WriteHeader(429)
			return
		}
		io.WriteString(w, `{"events":[],"next_cursor":""}`)
	})
	if _, err := c.EventsPage(context.Background(), EventQuery{View: "python"}); err != nil {
		t.Fatal(err)
	}
}

// pagedServer serves pages keyed by cursor: "" is the first.
func pagedServer(t *testing.T, pages map[string]string, seen *[]EventQuery) *Client {
	return newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/get_all_events_with_count/" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		var q EventQuery
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Fatal(err)
		}
		if seen != nil {
			*seen = append(*seen, q)
		}
		body, ok := pages[q.Cursor]
		if !ok {
			t.Errorf("unexpected cursor %q", q.Cursor)
			w.WriteHeader(400)
			return
		}
		io.WriteString(w, body)
	})
}

func row(id int) string {
	return `["2026-07-05T12:00:00Z","open","v",1,"m","low","python",` + itoa(id) + `]`
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestEachEvent_followsCursorThroughEmptyPages(t *testing.T) {
	// A short or empty page is not the last page (docs: Paging).
	var seen []EventQuery
	c := pagedServer(t, map[string]string{
		"":   `{"events":[` + row(1) + `],"next_cursor":"c1","scanned":10}`,
		"c1": `{"events":[],"next_cursor":"c2","scanned":10}`,
		"c2": `{"events":[` + row(2) + `,` + row(3) + `],"next_cursor":"","exhausted":true}`,
	}, &seen)
	var ids []int64
	pages := 0
	err := c.EachEvent(context.Background(), EventQuery{Severity: []string{"high"}}, func(e Event) error {
		ids = append(ids, e.ID)
		return nil
	}, func(p PageProgress) { pages = p.Pages })
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 || ids[2] != 3 || pages != 3 {
		t.Fatalf("ids=%v pages=%d", ids, pages)
	}
	for _, q := range seen {
		if len(q.Severity) != 1 {
			t.Fatalf("filters must be resent with every cursor: %+v", q)
		}
	}
}

func TestEachEvent_stopAndRepeatedCursor(t *testing.T) {
	c := pagedServer(t, map[string]string{
		"":  `{"events":[` + row(1) + `,` + row(2) + `],"next_cursor":"a"}`,
		"a": `{"events":[` + row(3) + `],"next_cursor":"a"}`,
	}, nil)
	n := 0
	err := c.EachEvent(context.Background(), EventQuery{}, func(Event) error {
		n++
		if n == 2 {
			return ErrStop
		}
		return nil
	}, nil)
	if err != nil || n != 2 {
		t.Fatalf("ErrStop: err=%v n=%d", err, n)
	}
	err = c.EachEvent(context.Background(), EventQuery{}, func(Event) error { return nil }, nil)
	if err == nil || !strings.Contains(err.Error(), "same cursor") {
		t.Fatalf("a repeating cursor must end the walk with an error, got %v", err)
	}
}

func TestExport(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/events_export" || r.URL.Query().Get("format") != "json" {
			t.Errorf("%s ?%s", r.URL.Path, r.URL.RawQuery)
		}
		var q EventQuery
		json.NewDecoder(r.Body).Decode(&q)
		if q.Cursor != "" {
			t.Error("export must not send a cursor")
		}
		io.WriteString(w, `{"count":0,"events":[],"truncated":false}`)
	})
	var buf bytes.Buffer
	if _, err := c.Export(context.Background(), EventQuery{Cursor: "x"}, "json", &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"truncated":false`) {
		t.Fatal(buf.String())
	}
	if _, err := c.Export(context.Background(), EventQuery{}, "xml", &buf); err == nil {
		t.Fatal("xml must be refused before any request")
	}
}

func TestRunsQueryParams(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("machine") != "web 01" || q.Get("q") != "app.py" || q.Get("before") != "b" || q.Get("limit") != "5" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		io.WriteString(w, `{"runs":[{"run_uid":"9f","cmdline":"es-python app.py","events":2,"occurrences":4}],"next_before":""}`)
	})
	p, err := c.Runs(context.Background(), RunsQuery{Machine: "web 01", Q: "app.py", Before: "b", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Runs) != 1 || p.Runs[0].Occurrences != 4 {
		t.Fatalf("%+v", p)
	}
}

func TestEventDetailAndCounts(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/event/42":
			io.WriteString(w, `{"trace":"T","origin":"O","runs":[{"run_uid":"r","count":2}]}`)
		case "/api/event_count/":
			if r.URL.Query().Get("view") != "python" {
				t.Errorf("view = %q", r.URL.Query().Get("view"))
			}
			io.WriteString(w, `{"count":3,"view":"python","event_limit":5000,"event_limit_monthly":true}`)
		case "/api/event_view_counts/":
			io.WriteString(w, `{"python":3,"browser":0}`)
		case "/api/event_names/":
			io.WriteString(w, `{"names":["open"]}`)
		case "/api/get_event_stats/":
			io.WriteString(w, `{"total_hits":3,"top_events":[{"where":"open","count":3}]}`)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	ctx := context.Background()
	d, err := c.Event(ctx, 42)
	if err != nil || d.Trace != "T" || len(d.Runs) != 1 || d.Runs[0].Count != 2 {
		t.Fatalf("%+v %v", d, err)
	}
	n, err := c.EventCount(ctx, "python")
	if err != nil || n.Count != 3 {
		t.Fatalf("%+v %v", n, err)
	}
	vc, err := c.ViewCounts(ctx, "")
	if err != nil || vc["python"] != 3 {
		t.Fatalf("%+v %v", vc, err)
	}
	names, err := c.EventNames(ctx)
	if err != nil || len(names) != 1 {
		t.Fatalf("%v %v", names, err)
	}
	s, err := c.Stats(ctx)
	if err != nil || s.TotalHits != 3 || s.TopEvents[0].Where != "open" {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestQueryOmitsEmptyFields(t *testing.T) {
	b, _ := json.Marshal(EventQuery{})
	if string(b) != "{}" {
		t.Fatalf("an empty query must be {} (no filters), got %s", b)
	}
}
