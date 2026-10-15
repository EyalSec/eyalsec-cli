package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// Account returns your profile, limits and permissions (GET /api/account/).
func (c *Client) Account(ctx context.Context) (*Account, error) {
	var a Account
	if err := c.getJSON(ctx, "/api/account/", nil, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// Machines lists every machine on your account (GET /api/get_all_machines/).
func (c *Client) Machines(ctx context.Context) ([]Machine, error) {
	var out struct {
		Machines []Machine `json:"machines"`
	}
	if err := c.getJSON(ctx, "/api/get_all_machines/", nil, &out); err != nil {
		return nil, err
	}
	return out.Machines, nil
}

// EventsPage returns one page of events (POST /api/get_all_events_with_count/).
//
// A short or empty page is not the last page: keep sending NextCursor until it
// comes back empty. EachEvent does that for you.
func (c *Client) EventsPage(ctx context.Context, q EventQuery) (*EventsPage, error) {
	var p EventsPage
	if err := c.postJSON(ctx, "/api/get_all_events_with_count/", nil, q, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ErrStop, returned from an EachEvent callback, ends the walk without error.
var ErrStop = errors.New("stop")

// PageProgress reports how far a walk has got, after each page.
type PageProgress struct {
	Pages          int
	Scanned        int64
	OldestExamined string
	HiddenBy       *HiddenBy
	// PageEvents and NextCursor describe the page just fetched, whose events
	// are passed to fn right after this call.
	PageEvents int
	NextCursor string
}

// EachEvent calls fn for every event matching q, following the cursor until
// the server says there is nothing more. q.Cursor is the starting point
// (normally empty). progress, when not nil, is called after every page.
func (c *Client) EachEvent(ctx context.Context, q EventQuery, fn func(Event) error, progress func(PageProgress)) error {
	var pp PageProgress
	seen := map[string]bool{}
	for {
		page, err := c.EventsPage(ctx, q)
		if err != nil {
			return err
		}
		pp.Pages++
		pp.Scanned += page.Scanned
		pp.OldestExamined = page.OldestExamined
		pp.HiddenBy = page.HiddenBy
		pp.PageEvents = len(page.Events)
		pp.NextCursor = page.NextCursor
		if progress != nil {
			progress(pp)
		}
		for _, e := range page.Events {
			if err := fn(e); err != nil {
				if errors.Is(err, ErrStop) {
					return nil
				}
				return err
			}
		}
		if page.NextCursor == "" {
			return nil
		}
		if seen[page.NextCursor] {
			return fmt.Errorf("the API returned the same cursor twice; stopping after %d pages", pp.Pages)
		}
		seen[page.NextCursor] = true
		q.Cursor = page.NextCursor
	}
}

// Event returns the large fields of one event (GET /api/event/{id}).
func (c *Client) Event(ctx context.Context, id int64) (*EventDetail, error) {
	var d EventDetail
	if err := c.getJSON(ctx, "/api/event/"+strconv.FormatInt(id, 10), nil, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Export writes every event matching q to w, as "csv" or "json"
// (POST /api/events_export). The server stops at 50,000 rows and says so in
// the file itself.
func (c *Client) Export(ctx context.Context, q EventQuery, format string, w io.Writer) (int64, error) {
	if format != "csv" && format != "json" {
		return 0, fmt.Errorf("export format must be csv or json, not %q", format)
	}
	q.Cursor = ""
	resp, err := c.do(ctx, http.MethodPost, "/api/events_export", url.Values{"format": {format}}, q)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return io.Copy(w, resp.Body)
}

// Runs lists the runs behind your events, newest first (GET /api/runs/).
func (c *Client) Runs(ctx context.Context, q RunsQuery) (*RunsPage, error) {
	v := url.Values{}
	if q.Machine != "" {
		v.Set("machine", q.Machine)
	}
	if q.Q != "" {
		v.Set("q", q.Q)
	}
	if q.Before != "" {
		v.Set("before", q.Before)
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	var p RunsPage
	if err := c.getJSON(ctx, "/api/runs/", v, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Stats returns the dashboard summary (GET /api/get_event_stats/).
func (c *Client) Stats(ctx context.Context) (*Stats, error) {
	var s Stats
	if err := c.getJSON(ctx, "/api/get_event_stats/", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// EventCount returns how many events count toward the quota, for one product
// view or (view "") across all of them (GET /api/event_count/).
func (c *Client) EventCount(ctx context.Context, view string) (*EventCount, error) {
	var v url.Values
	if view != "" {
		v = url.Values{"view": {view}}
	}
	var n EventCount
	if err := c.getJSON(ctx, "/api/event_count/", v, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

// ViewCounts returns how many events each product's list shows
// (GET /api/event_view_counts/). bucket is live (default), suppressed or all.
func (c *Client) ViewCounts(ctx context.Context, bucket string) (map[string]int64, error) {
	var v url.Values
	if bucket != "" {
		v = url.Values{"bucket": {bucket}}
	}
	out := map[string]int64{}
	if err := c.getJSON(ctx, "/api/event_view_counts/", v, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// EventNames lists the distinct sink labels across your events
// (GET /api/event_names/).
func (c *Client) EventNames(ctx context.Context) ([]string, error) {
	var out struct {
		Names []string `json:"names"`
	}
	if err := c.getJSON(ctx, "/api/event_names/", nil, &out); err != nil {
		return nil, err
	}
	return out.Names, nil
}
