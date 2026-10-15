// Package api is a small client for the EyalSec API, documented at
// https://eyalsec.com/docs/api.
//
// It covers the read side of the API: your account, machines, events (one
// page, every page, one event's detail, export), runs and statistics. Every
// call is authenticated with an API key sent in the X-API-Key header; a
// read-only key is enough for all of them.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the hosted EyalSec service.
const DefaultBaseURL = "https://eyalsec.com"

// Client calls the EyalSec API. The zero value is not usable; use New.
type Client struct {
	// BaseURL is your EyalSec address, such as https://eyalsec.com.
	BaseURL string
	// APIKey is sent in the X-API-Key header of every request.
	APIKey string
	// UserAgent identifies the caller in the server's activity log.
	UserAgent string
	// HTTP is the underlying client. New sets a 60 second timeout.
	HTTP *http.Client
	// MaxRetries is how many times a request answered 429 is retried after
	// waiting for its Retry-After. Zero disables retrying.
	MaxRetries int
	// MaxRetryWait caps a single Retry-After wait.
	MaxRetryWait time.Duration

	sleep func(context.Context, time.Duration) error
}

// New returns a client for baseURL (DefaultBaseURL when empty) signed with
// apiKey.
func New(baseURL, apiKey string) (*Client, error) {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	u, err := ValidateBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		BaseURL:      u,
		APIKey:       apiKey,
		UserAgent:    "eyalsec-cli",
		HTTP:         &http.Client{Timeout: 60 * time.Second},
		MaxRetries:   3,
		MaxRetryWait: 60 * time.Second,
	}, nil
}

// ValidateBaseURL checks that raw is an https:// address (plain http is
// accepted only for localhost, for testing) and returns it without a trailing
// slash. An API key must never travel in clear text.
func ValidateBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q is not a valid address; use the form https://eyalsec.com", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		h := u.Hostname()
		if h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return "", fmt.Errorf("%q uses http://; the API key must travel over https://", raw)
		}
	default:
		return "", fmt.Errorf("%q is not an http(s) address; use the form https://eyalsec.com", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%q should be the bare address, without a query or fragment", raw)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// Error is a non-2xx answer from the API.
type Error struct {
	Status     int
	Message    string // the server's message, from {"error": ...} or the plain-text body
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, msg)
}

// IsStatus reports whether err is an *Error with the given HTTP status.
func IsStatus(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == status
}

func (c *Client) wait(ctx context.Context, d time.Duration) error {
	if c.sleep != nil {
		return c.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// do sends one request and returns the response for a 2xx answer. The caller
// closes the body. A 429 is retried after its Retry-After, up to MaxRetries.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any) (*http.Response, error) {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = b
	}
	target := c.BaseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	for attempt := 0; ; attempt++ {
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-API-Key", c.APIKey)
		req.Header.Set("Accept", "application/json")
		if c.UserAgent != "" {
			req.Header.Set("User-Agent", c.UserAgent)
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}
		apiErr := readError(resp)
		if resp.StatusCode == http.StatusTooManyRequests && attempt < c.MaxRetries {
			d := apiErr.RetryAfter
			if d <= 0 {
				d = time.Duration(attempt+1) * 2 * time.Second
			}
			if c.MaxRetryWait > 0 && d > c.MaxRetryWait {
				d = c.MaxRetryWait
			}
			if err := c.wait(ctx, d); err != nil {
				return nil, err
			}
			continue
		}
		return nil, apiErr
	}
}

func readError(resp *http.Response) *Error {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	e := &Error{Status: resp.StatusCode}
	if s := resp.Header.Get("Retry-After"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n >= 0 {
			e.RetryAfter = time.Duration(n) * time.Second
		}
	}
	var j struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(b, &j) == nil && j.Error != "" {
		e.Message = j.Error
	} else if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "html") {
		e.Message = strings.TrimSpace(string(b))
	}
	if len(e.Message) > 500 {
		e.Message = e.Message[:500] + "..."
	}
	return e
}

// getJSON / postJSON decode a JSON answer into out.
func (c *Client) getJSON(ctx context.Context, path string, query url.Values, out any) error {
	resp, err := c.do(ctx, http.MethodGet, path, query, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decode(resp.Body, out)
}

func (c *Client) postJSON(ctx context.Context, path string, query url.Values, body, out any) error {
	resp, err := c.do(ctx, http.MethodPost, path, query, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decode(resp.Body, out)
}

func decode(r io.Reader, out any) error {
	if err := json.NewDecoder(r).Decode(out); err != nil {
		return fmt.Errorf("the API answered with something that is not the JSON expected: %w", err)
	}
	return nil
}
