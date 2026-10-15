// Package cli implements the eyalsec-cli command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"eyalsec.com/cli/api"
)

// version is set at build time with -ldflags "-X eyalsec.com/cli/internal/cli.version=v0.1.0".
var version = ""

// Version returns the CLI version: the build-time stamp, else the module
// version `go install` recorded, else "dev".
func Version() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// errUsage marks an error as a usage mistake (exit status 2).
type errUsage struct{ msg string }

func (e errUsage) Error() string { return e.msg }

func usagef(format string, a ...any) error { return errUsage{fmt.Sprintf(format, a...)} }

// App holds everything a command touches, so tests can run it in-process.
type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Env    func(string) string
	// HTTP, when set, replaces the API client's HTTP client (tests).
	HTTP *http.Client
	// StdinIsTerminal reports whether Stdin is an interactive terminal.
	StdinIsTerminal func() bool
	// StdoutIsTerminal reports whether Stdout is an interactive terminal.
	StdoutIsTerminal func() bool
}

// Main runs the CLI with os-level I/O and returns the exit status.
func Main(args []string) int {
	app := &App{
		Stdin:            os.Stdin,
		Stdout:           os.Stdout,
		Stderr:           os.Stderr,
		Env:              os.Getenv,
		StdinIsTerminal:  func() bool { return isTerminal(os.Stdin) },
		StdoutIsTerminal: func() bool { return isTerminal(os.Stdout) },
	}
	return app.Run(context.Background(), args)
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

const mainUsage = `eyalsec-cli reads your EyalSec events and machines from a terminal or a script.

Usage:
  eyalsec-cli <command> [flags]

Commands:
  whoami                 Show the account your API key belongs to
  machines list          List your machines
  events list            List events, newest first
  events search TEXT     List events whose value contains TEXT
  events get ID          Show one event's full detail: trace, origin, runs
  events export          Download every matching event as CSV or JSON
  events stats           The dashboard summary: totals and top event types
  events count           Events counted toward your quota, per product
  events names           The distinct event names (sinks) you have
  runs list              The program runs behind your events
  config set-key         Save your API key (read from standard input)
  config set-url URL     Save your EyalSec address (default https://eyalsec.com)
  config show            Show the address and key in use, and where each came from
  config path            Print the config file's location
  version                Print the version

Run "eyalsec-cli <command> -h" for a command's flags.

Your API key comes from EYALSEC_API_KEY, or from the config file that
"eyalsec-cli config set-key" writes. Create the key on your dashboard under
Settings > API access; a read-only key is enough for every command.
Docs: https://eyalsec.com/docs/api
`

// Run executes one command line and returns the exit status.
func (a *App) Run(ctx context.Context, args []string) int {
	if a.Env == nil {
		a.Env = func(string) string { return "" }
	}
	if a.StdinIsTerminal == nil {
		a.StdinIsTerminal = func() bool { return false }
	}
	if a.StdoutIsTerminal == nil {
		a.StdoutIsTerminal = func() bool { return false }
	}
	err := a.dispatch(ctx, args)
	if err == nil {
		return exitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	var rep errReported
	if errors.As(err, &rep) {
		return exitUsage
	}
	var ue errUsage
	if errors.As(err, &ue) {
		fmt.Fprintf(a.Stderr, "eyalsec-cli: %s\n", ue.msg)
		fmt.Fprintln(a.Stderr, `Run "eyalsec-cli -h" for the list of commands.`)
		return exitUsage
	}
	fmt.Fprintf(a.Stderr, "eyalsec-cli: %s\n", explain(err))
	return exitError
}

func (a *App) dispatch(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(a.Stderr, mainUsage)
		return usagef("no command given")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Fprint(a.Stdout, mainUsage)
		return nil
	case "version", "--version", "-v":
		fmt.Fprintf(a.Stdout, "eyalsec-cli %s (%s/%s)\n", Version(), runtime.GOOS, runtime.GOARCH)
		return nil
	case "whoami":
		return a.cmdWhoami(ctx, rest)
	case "machines", "machine":
		return a.sub(ctx, "machines", rest, map[string]func(context.Context, []string) error{
			"list": a.cmdMachinesList, "ls": a.cmdMachinesList,
		})
	case "events", "event":
		return a.sub(ctx, "events", rest, map[string]func(context.Context, []string) error{
			"list":   a.cmdEventsList,
			"ls":     a.cmdEventsList,
			"search": a.cmdEventsSearch,
			"get":    a.cmdEventsGet,
			"show":   a.cmdEventsGet,
			"export": a.cmdEventsExport,
			"stats":  a.cmdEventsStats,
			"count":  a.cmdEventsCount,
			"names":  a.cmdEventsNames,
		})
	case "runs", "run":
		return a.sub(ctx, "runs", rest, map[string]func(context.Context, []string) error{
			"list": a.cmdRunsList, "ls": a.cmdRunsList,
		})
	case "config":
		return a.sub(ctx, "config", rest, map[string]func(context.Context, []string) error{
			"set-key": a.cmdConfigSetKey,
			"set-url": a.cmdConfigSetURL,
			"show":    a.cmdConfigShow,
			"path":    a.cmdConfigPath,
		})
	default:
		return usagef("unknown command %q", cmd)
	}
}

func (a *App) sub(ctx context.Context, group string, args []string, cmds map[string]func(context.Context, []string) error) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		names := make([]string, 0, len(cmds))
		for _, line := range strings.Split(mainUsage, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), group+" ") {
				names = append(names, line)
			}
		}
		fmt.Fprintf(a.Stdout, "Usage:\n  eyalsec-cli %s <subcommand> [flags]\n\nSubcommands:\n%s\n", group, strings.Join(names, "\n"))
		if len(args) == 0 {
			return usagef("%s needs a subcommand", group)
		}
		return nil
	}
	f, ok := cmds[args[0]]
	if !ok {
		return usagef("unknown subcommand %q for %s", args[0], group)
	}
	return f(ctx, args[1:])
}

// common holds the flags every API command takes.
type common struct {
	url    string
	config string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.url, "url", "", "your EyalSec address (default: EYALSEC_URL, the config file, or https://eyalsec.com)")
	fs.StringVar(&c.config, "config", "", "config file to read (default: EYALSEC_CONFIG or the user config directory)")
}

func (a *App) configPath(c *common) (string, error) {
	if c != nil && c.config != "" {
		return c.config, nil
	}
	return defaultConfigPath(a.Env)
}

// client builds an API client from the flags, the environment and the config
// file.
func (a *App) client(c *common) (*api.Client, error) {
	path, err := a.configPath(c)
	if err != nil {
		return nil, err
	}
	cfg, err := loadConfig(a.Env, path, c.url)
	if err != nil {
		return nil, err
	}
	if cfg.APIKey == "" {
		return nil, errors.New("no API key found. Create one on your dashboard under Settings > API access " +
			"(a read-only key is enough), then either export EYALSEC_API_KEY=es2_... or run: eyalsec-cli config set-key")
	}
	if cfg.KeySource == path && configTooOpen(path) {
		fmt.Fprintf(a.Stderr, "eyalsec-cli: warning: %s can be read by other users; run: chmod 600 %s\n", path, path)
	}
	cl, err := api.New(cfg.URL, cfg.APIKey)
	if err != nil {
		return nil, err
	}
	cl.UserAgent = fmt.Sprintf("eyalsec-cli/%s (%s/%s)", Version(), runtime.GOOS, runtime.GOARCH)
	if a.HTTP != nil {
		cl.HTTP = a.HTTP
	}
	return cl, nil
}

// explain turns an API error into a sentence that says what to do next.
func explain(err error) string {
	var e *api.Error
	if !errors.As(err, &e) {
		return err.Error()
	}
	msg := e.Message
	switch e.Status {
	case http.StatusUnauthorized:
		return "the API key was not accepted: it is missing, mistyped, revoked or expired. " +
			"Create a new one under Settings > API access, then run: eyalsec-cli config set-key"
	case http.StatusForbidden:
		if msg == "" {
			msg = "not allowed"
		}
		return fmt.Sprintf("the server refused this request (403): %s. If you expected access, write to support@eyalsec.com", msg)
	case http.StatusNotFound:
		return "not found (404). An id that belongs to another account is also answered this way"
	case http.StatusTooManyRequests:
		return fmt.Sprintf("rate limit reached (429) and retries ran out; wait %s and try again", e.RetryAfter)
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		if msg == "" {
			msg = "the request was not accepted"
		}
		// Name the flag the user typed, not the wire field it became.
		msg = strings.NewReplacer("whitelist_repr", "--where", "blacklist_repr", "--exclude").Replace(msg)
		return fmt.Sprintf("the server could not use this request (%d): %s", e.Status, msg)
	}
	if e.Status >= 500 {
		return fmt.Sprintf("the server had a problem answering (%d). Please try again; if it keeps happening, write to support@eyalsec.com", e.Status)
	}
	return e.Error()
}

// parseInterspersed parses flags that may come before or after positional
// arguments ("events get 42 -o json" and "events get -o json 42" both work).
// "--" ends flag parsing.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		// flag.Parse stops at "--" and drops it; detect that by comparing
		// with the raw arguments.
		consumed := len(args) - len(rest)
		if consumed > 0 && args[consumed-1] == "--" {
			return append(pos, rest...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func newFlagSet(a *App, name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(a.Stderr, "Usage: eyalsec-cli %s\n\nFlags:\n", usage)
		fs.PrintDefaults()
	}
	return fs
}

// errReported is a usage error the flag package has already printed.
type errReported struct{ error }

// flagErr maps a flag-parsing failure to a usage error (help stays help).
func flagErr(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return err
	}
	return errReported{err}
}
