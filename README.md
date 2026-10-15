# eyalsec-cli

Read your EyalSec events and machines from a terminal, a cron job or a CI step. `eyalsec-cli` lists and searches your events, shows one event's full detail, exports everything that matches a filter as CSV or JSON, and lists your machines and runs, all through the [EyalSec API](https://eyalsec.com/docs/api). If you already use `curl` and `jq` against the API, this saves you the paging, the quoting and the row decoding.

[![Website](https://img.shields.io/badge/website-eyalsec.com-e8b04b)](https://eyalsec.com)
[![API docs](https://img.shields.io/badge/docs-API-2a2c27)](https://eyalsec.com/docs/api)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/EyalSec/eyalsec-cli/badge)](https://scorecard.dev/viewer/?uri=github.com/EyalSec/eyalsec-cli)

EyalSec follows untrusted data (network input, files, environment variables and more) through your running program and reports when it reaches a risky operation: a SQL query, a shell command, deserialization, a file path. Each event names the operation, the line of code, the value it received and where the untrusted part came from. This tool reads those events; it never changes anything on your account.

```console
$ eyalsec-cli events list --severity critical,high --from 2026-10-01
ID        SEEN              SEVERITY  MACHINE  EVENT           VALUE                                                  COUNT
90213     2026-10-14 09:12  critical  web-01   os system       ping -c1 example.com; id                               2
90210     2026-10-13 17:40  high      web-01   sqlite execute  SELECT id FROM products WHERE name LIKE '%' OR 1=1 --  5
```

## What you need

- An EyalSec account and an API key. Create the key on your dashboard under **Settings > API access**. A **read-only key** is all this tool needs, and it is the one we recommend: see [API keys](https://eyalsec.com/docs/api-keys).
- Linux, macOS or Windows, on x86_64 or arm64.

No account yet? [Book a live demo](https://eyalsec.com/contact) and we will set one up with you. Pricing is at [eyalsec.com/pricing](https://eyalsec.com/pricing).

## Install

**Homebrew** (macOS and Linux):

```bash
brew install eyalsec/tap/eyalsec-cli
```

**Debian and Ubuntu**, from the [latest release](https://github.com/EyalSec/eyalsec-cli/releases/latest):

```bash
curl -LO https://github.com/EyalSec/eyalsec-cli/releases/download/v0.1.0/eyalsec-cli_0.1.0_amd64.deb
sudo apt install ./eyalsec-cli_0.1.0_amd64.deb
```

**Fedora, RHEL, Rocky, Alma and openSUSE**:

```bash
sudo dnf install https://github.com/EyalSec/eyalsec-cli/releases/download/v0.1.0/eyalsec-cli-0.1.0-1.x86_64.rpm
```

On arm64, use the `arm64` `.deb` or the `aarch64` `.rpm` from the same release.

**Any other system**: download the `.tar.gz` (or the `.zip` on Windows) for your platform from the [release page](https://github.com/EyalSec/eyalsec-cli/releases/latest) and put `eyalsec-cli` on your `PATH`. On macOS, a file downloaded with a browser is quarantined until you clear it with `xattr -d com.apple.quarantine eyalsec-cli`; Homebrew installs and `curl` downloads are not affected.

**With Go** 1.22 or newer:

```bash
go install eyalsec.com/cli/cmd/eyalsec-cli@latest
```

### Check what you downloaded

Every release file is listed in `checksums.txt` and carries a signed [build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations), which proves it was built from this repository by its release workflow:

```bash
sha256sum --ignore-missing -c checksums.txt
gh attestation verify eyalsec-cli_0.1.0_linux_amd64.tar.gz --repo EyalSec/eyalsec-cli
```

## Give it your key

Either save the key once (it is read from standard input, so it stays out of your shell history, and the file is created readable only by you):

```bash
eyalsec-cli config set-key
```

or set it in the environment, which is handy in CI:

```bash
export EYALSEC_API_KEY=es2_your_read_only_key
```

`set-key` checks the key against the API before saving it and tells you which account it belongs to. Then:

```console
$ eyalsec-cli whoami
Account             alice
Address             https://eyalsec.com
Machines allowed    5 per product
Event quota         5000 per month per product
Raise rules         off
Two-factor sign-in  on
```

| Setting | Environment | Config file key | Default |
|---|---|---|---|
| API key | `EYALSEC_API_KEY` | `api_key` | none |
| Your EyalSec address | `EYALSEC_URL` (or `--url`) | `url` | `https://eyalsec.com` |
| Config file location | `EYALSEC_CONFIG` (or `--config`) | | `~/.config/eyalsec/config` on Linux, `~/Library/Application Support/eyalsec/config` on macOS, `%AppData%\eyalsec\config` on Windows |

The environment wins over the config file. `eyalsec-cli config show` prints the address and key in use (the key masked) and where each one came from. The address must be `https://`, so the key never travels in clear text.

## Commands

| Command | What it does |
|---|---|
| `whoami` | The account your key belongs to, with its limits |
| `machines list` | Your machines: product, status, OS, build, and whether an update is available |
| `events list` | Events, newest first, filtered like the events page |
| `events search TEXT` | Events whose value contains `TEXT` (`--regex`, `--field trace`, ...) |
| `events get ID` | One event's full detail: where the data came in, the stack trace, source lines, runs |
| `events export` | Every matching event as one CSV or JSON file |
| `events stats` | The dashboard summary: totals and the top event types |
| `events count` | How many events each product's list shows, or (`--view`) the count toward your quota |
| `events names` | The distinct event names (sinks) you have, for building a filter |
| `runs list` | The program runs behind your events, with their command lines |
| `config set-key`, `config set-url`, `config show`, `config path` | Manage the saved settings |

Run `eyalsec-cli <command> -h` for every flag.

### Filters

`events list`, `events search` and `events export` take the same filters as the [events query](https://eyalsec.com/docs/api-events#query-body):

| Flag | Keeps |
|---|---|
| `--view python` or `browser` | one product's events |
| `--severity critical,high` | those severities |
| `--from 2026-10-01 --to 2026-10-14` | that date range (`--to` includes the whole day) |
| `--machine web-01` | one machine, by name |
| `--source socket,file` | events whose untrusted data came from those sources |
| `--tag sqli` | events carrying that impact class |
| `--where REGEX`, `--exclude REGEX` | events whose name (sink) matches, or does not |
| `--cond field:op:value` | the condition builder, repeatable; `--any` matches any instead of all |
| `--run RUN_ID` | the events of one run (from `runs list`) |
| `--bucket suppressed` or `all` | events the sanitizer hid, or both kinds (default: only those shown) |
| `--sort severity` | most severe first (default: newest first) |

Condition fields include `sink`, `value`, `trace`, `origin`, `detail`, `command` and `environment` for es-python, and `payload`, `source`, `url`, `page`, `script`, `extension` and `host` for es-chromium. Operators are `contains`, `is`, `starts`, `ends`, `regex` and `empty`; put `!` before one to negate it. See [conditions](https://eyalsec.com/docs/advanced-search#conditions).

### Examples

```bash
# Everything critical from one machine this month, most severe first
eyalsec-cli events list --machine web-01 --severity critical --from 2026-10-01 --sort severity

# Events whose stack trace passes through one file
eyalsec-cli events list --view python --cond 'trace:contains:views.py'

# Command-injection-shaped values, excluding a noisy sink
eyalsec-cli events search --regex '[;|&] *(id|whoami)' --exclude '^open$'

# The full story of one event
eyalsec-cli events get 90213

# A spreadsheet of this week's high and critical events
eyalsec-cli events export --format csv -O findings.csv --severity critical,high --from 2026-10-08

# Feed jq, one JSON object per line
eyalsec-cli events list --limit 0 -o jsonl | jq -r 'select(.severity == "critical") | .where' | sort | uniq -c

# Fail a CI job when today brought a new critical event
test "$(eyalsec-cli events list --severity critical --from "$(date -u +%F)" --limit 1 -o json | jq length)" -eq 0
```

## Output

Lists print a table by default; `-o json`, `-o jsonl` and `-o csv` are for programs. JSON uses the field names of the [API documentation](https://eyalsec.com/docs/api-events#event-row) (`where`, `str_repr`, `machine_name`, ...), with the API's positional rows turned into named objects.

A few things worth knowing:

- **Values are shown safely.** An event's value is untrusted data by definition, so in tables and text output every control character, terminal escape sequence and bidirectional override is printed as an escape such as `\x1b` rather than sent to your terminal. JSON output keeps the value exactly.
- **CSV cells are guarded against spreadsheet formulas.** A cell that begins with `=`, `+`, `-`, `@` or a tab gets a leading `'`, so a value such as `=HYPERLINK(...)` opens as text. Pass `--raw-csv` for the exact values. `events export` writes the server's own file unchanged.
- **Every page is followed.** The API can answer a selective filter with a short or empty page that still has more behind it; `events list` keeps following the cursor until the server says it is done, or until `--limit` (default 100, `0` for everything). `--progress` shows how far back it has looked.
- **Rate limits are respected.** A `429` is retried after the `Retry-After` the server sends, up to three times.
- **An export stops at 50,000 rows**, as the API does, and the tool tells you when that happened.

Exit status is `0` on success, `1` when the API or the network refused, and `2` for a mistake on the command line.

## Use it from Go

The client is a small package with no dependencies outside the standard library:

```go
import "eyalsec.com/cli/api"

c, _ := api.New("", os.Getenv("EYALSEC_API_KEY")) // "" means https://eyalsec.com
err := c.EachEvent(ctx, api.EventQuery{Severity: []string{"critical"}}, func(e api.Event) error {
	fmt.Println(e.ID, e.Where, e.Machine)
	return nil
}, nil)
```

## Develop

```bash
go test ./...                     # unit tests against a fake API
EYALSEC_LIVE=1 EYALSEC_API_KEY=es2_... go test ./internal/cli -run TestLive -v   # read-only pass against your account
```

Releases are built by [`.github/workflows/release.yml`](.github/workflows/release.yml) when a `v*` tag is pushed. Distribution packaging (Fedora COPR, openSUSE OBS, a Launchpad PPA, Cloudsmith) lives in [`packaging/`](packaging/README.md).

## Help and security

Questions and bugs: open an issue, or write to support@eyalsec.com. Please report a security problem in this tool or in EyalSec privately to security@eyalsec.com rather than in a public issue.

## License

MIT. See [LICENSE](LICENSE).
