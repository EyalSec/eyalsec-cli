package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Account is the answer of GET /api/account/.
type Account struct {
	Username          string `json:"username"`
	Email             string `json:"email"`
	Timezone          string `json:"timezone"`
	EmailVerified     bool   `json:"email_verified"`
	TOTPEnabled       bool   `json:"totp_enabled"`
	Email2FAEnabled   bool   `json:"email_2fa_enabled"`
	MachineLimit      int    `json:"machine_limit"`
	EventLimit        int    `json:"event_limit"`
	EventLimitMonthly bool   `json:"event_limit_monthly"`
	GrantRaise        bool   `json:"grant_raise"`
}

// Impact is one impact class of an event, such as {"sqli", "high"}.
type Impact struct {
	Label    string `json:"label"`
	Severity string `json:"sev"`
}

// Label is one of your triage labels.
type Label struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

// Event is one row of the events query. On the wire it is an array of values
// in a fixed order (https://eyalsec.com/docs/api-events#event-row); this type
// gives each one a name. Values the server adds at the end in future are
// ignored.
type Event struct {
	CreatedAt      time.Time `json:"created_at"`
	Where          string    `json:"where"`
	Value          string    `json:"str_repr"`
	Count          int64     `json:"count"`
	Machine        string    `json:"machine_name"`
	Severity       string    `json:"severity"`
	AgentKind      string    `json:"agent_kind"`
	ID             int64     `json:"id"`
	SourceLabel    string    `json:"source_label"`
	Context        string    `json:"context"`
	Suppressed     bool      `json:"suppressed"`
	SanitizeReason string    `json:"sanitize_reason"`
	Impact         []Impact  `json:"impact"`
	Labels         []Label   `json:"labels"`
	HasComment     bool      `json:"has_comment"`
	Extension      string    `json:"extension"`
	TaintSource    string    `json:"taint_source"`
}

// UnmarshalJSON reads the positional array form of an event row.
func (e *Event) UnmarshalJSON(b []byte) error {
	if isObject(b) {
		// The named form this package writes (for example the CLI's JSON output).
		type plain Event
		return json.Unmarshal(b, (*plain)(e))
	}
	var row []json.RawMessage
	if err := json.Unmarshal(b, &row); err != nil {
		return fmt.Errorf("event row: %w", err)
	}
	fields := []any{
		&e.CreatedAt, &e.Where, &e.Value, &e.Count, &e.Machine, &e.Severity,
		&e.AgentKind, &e.ID, &e.SourceLabel, &e.Context, &e.Suppressed,
		&e.SanitizeReason, &e.Impact, &e.Labels, &e.HasComment, &e.Extension,
		&e.TaintSource,
	}
	return unmarshalRow(row, fields, "event")
}

// Machine is one row of GET /api/get_all_machines/
// (https://eyalsec.com/docs/api-machines#machine-row).
type Machine struct {
	CreatedAt      time.Time `json:"created_at"`
	Name           string    `json:"machine_name"`
	Status         string    `json:"status"`
	PublicID       string    `json:"public_id"`
	OSType         string    `json:"os_type"`
	InstalledBuild string    `json:"installed_build"`
	CurrentBuild   string    `json:"current_build"`
	PythonVersion  string    `json:"python_version"`
	SocketOnly     bool      `json:"socket_only"`
	CloneLocked    bool      `json:"clone_locked"`
	Stalled        bool      `json:"stalled"`
	StaleAgent     bool      `json:"stale_agent"`
	AgentKind      string    `json:"agent_kind"`
}

// UpdateAvailable reports whether a newer build exists for the machine.
func (m Machine) UpdateAvailable() bool {
	return m.InstalledBuild != "" && m.CurrentBuild != "" && m.InstalledBuild != m.CurrentBuild
}

// UnmarshalJSON reads the positional array form of a machine row.
func (m *Machine) UnmarshalJSON(b []byte) error {
	if isObject(b) {
		type plain Machine
		return json.Unmarshal(b, (*plain)(m))
	}
	var row []json.RawMessage
	if err := json.Unmarshal(b, &row); err != nil {
		return fmt.Errorf("machine row: %w", err)
	}
	fields := []any{
		&m.CreatedAt, &m.Name, &m.Status, &m.PublicID, &m.OSType,
		&m.InstalledBuild, &m.CurrentBuild, &m.PythonVersion, &m.SocketOnly,
		&m.CloneLocked, &m.Stalled, &m.StaleAgent, &m.AgentKind,
	}
	return unmarshalRow(row, fields, "machine")
}

func isObject(b []byte) bool {
	t := bytes.TrimLeft(b, " \t\r\n")
	return len(t) > 0 && t[0] == '{'
}

// unmarshalRow decodes row[i] into fields[i]. A null value, a missing trailing
// value or an empty timestamp leaves the field at its zero value.
func unmarshalRow(row []json.RawMessage, fields []any, what string) error {
	for i, f := range fields {
		if i >= len(row) {
			break
		}
		raw := row[i]
		if string(raw) == "null" {
			continue
		}
		if t, ok := f.(*time.Time); ok {
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf("%s row value %d: %w", what, i, err)
			}
			if s == "" {
				continue
			}
			parsed, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				return fmt.Errorf("%s row value %d: %w", what, i, err)
			}
			*t = parsed
			continue
		}
		if err := json.Unmarshal(raw, f); err != nil {
			return fmt.Errorf("%s row value %d: %w", what, i, err)
		}
	}
	return nil
}

// Scope is the events page's scope bar.
type Scope struct {
	Mode         string `json:"mode"` // is, ends or regex
	Value        string `json:"value"`
	IncludeEmpty bool   `json:"include_empty,omitempty"`
}

// Condition is one row of the condition builder
// (https://eyalsec.com/docs/advanced-search#conditions).
type Condition struct {
	Field  string `json:"field"`
	Op     string `json:"op"`
	Value  string `json:"value"`
	Negate bool   `json:"negate,omitempty"`
}

// Advanced is the condition builder: Match is "all" or "any".
type Advanced struct {
	Match      string      `json:"match"`
	Conditions []Condition `json:"conditions"`
}

// EventQuery is the body of the events query and the export. Every field is
// optional (https://eyalsec.com/docs/api-events#query-body).
type EventQuery struct {
	Cursor        string    `json:"cursor,omitempty"`
	Sort          string    `json:"sort,omitempty"`
	View          string    `json:"view,omitempty"`
	Bucket        string    `json:"bucket,omitempty"`
	WhitelistRepr string    `json:"whitelist_repr,omitempty"`
	BlacklistRepr string    `json:"blacklist_repr,omitempty"`
	From          string    `json:"from,omitempty"`
	To            string    `json:"to,omitempty"`
	Machine       string    `json:"machine,omitempty"`
	Severity      []string  `json:"severity,omitempty"`
	Sources       []string  `json:"sources,omitempty"`
	Tags          []string  `json:"tags,omitempty"`
	Labels        []int     `json:"labels,omitempty"`
	XSSOnly       bool      `json:"xss_only,omitempty"`
	Scope         *Scope    `json:"scope,omitempty"`
	Advanced      *Advanced `json:"advanced,omitempty"`
}

// HiddenBy names the Hide rule that hides every event in the view.
type HiddenBy struct {
	ID    int64  `json:"id"`
	Label string `json:"label"`
}

// EventsPage is one answer of the events query.
type EventsPage struct {
	Events            []Event   `json:"events"`
	NextCursor        string    `json:"next_cursor"`
	Scanned           int64     `json:"scanned"`
	Exhausted         bool      `json:"exhausted"`
	OldestExamined    string    `json:"oldest_examined"`
	EventLimit        int64     `json:"event_limit"`
	EventLimitMonthly bool      `json:"event_limit_monthly"`
	HiddenBy          *HiddenBy `json:"hidden_by,omitempty"`
}

// Run is one program invocation behind an event.
type Run struct {
	RunUID      string `json:"run_uid"`
	Cmdline     string `json:"cmdline"`
	Env         string `json:"env,omitempty"`
	Count       int64  `json:"count,omitempty"`
	Events      int64  `json:"events,omitempty"`
	Occurrences int64  `json:"occurrences,omitempty"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
}

// ExtensionInfo names the browser extension an es-chromium event came from.
type ExtensionInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Label   string `json:"label"`
}

// EventDetail is the answer of GET /api/event/{id}: the large fields the
// events list leaves out.
type EventDetail struct {
	Trace       string         `json:"trace"`
	Source      string         `json:"source"`
	Origin      string         `json:"origin"`
	ReprCreated string         `json:"repr_created"`
	SourceCode  string         `json:"source_code"`
	SinkCode    string         `json:"sink_code"`
	Detail      string         `json:"detail"`
	RuleSource  string         `json:"rule_source,omitempty"`
	Comment     string         `json:"comment"`
	Extension   *ExtensionInfo `json:"extension,omitempty"`
	Runs        []Run          `json:"runs"`
}

// RunsQuery filters GET /api/runs/.
type RunsQuery struct {
	Machine string
	Q       string
	Before  string
	Limit   int
}

// RunsPage is one answer of GET /api/runs/.
type RunsPage struct {
	Runs       []Run  `json:"runs"`
	NextBefore string `json:"next_before"`
}

// NameCount is a {where, count} pair in the statistics.
type NameCount struct {
	Where string `json:"where"`
	Count int64  `json:"count"`
}

// TimedCount is a recent event in the statistics.
type TimedCount struct {
	Time  string `json:"time"`
	Where string `json:"where"`
	Count int64  `json:"count"`
}

// DayCount is one day of the 14-day timeline.
type DayCount struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

// Stats is the answer of GET /api/get_event_stats/.
type Stats struct {
	TotalHits       int64        `json:"total_hits"`
	UniqueTypes     int64        `json:"unique_types"`
	Last1h          int64        `json:"last_1h"`
	Last24h         int64        `json:"last_24h"`
	Last7d          int64        `json:"last_7d"`
	TopEvents       []NameCount  `json:"top_events"`
	Recent          []TimedCount `json:"recent"`
	Timeline14d     []DayCount   `json:"timeline_14d"`
	FirstDetection  string       `json:"first_detection,omitempty"`
	LatestDetection string       `json:"latest_detection,omitempty"`
}

// EventCount is the answer of GET /api/event_count/.
type EventCount struct {
	Count             int64  `json:"count"`
	View              string `json:"view"`
	EventLimit        int64  `json:"event_limit"`
	EventLimitMonthly bool   `json:"event_limit_monthly"`
}
