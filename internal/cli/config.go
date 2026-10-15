package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Config is what the CLI needs to reach the API.
type Config struct {
	APIKey string
	URL    string

	// Where each value came from, for `config show`.
	KeySource string
	URLSource string
}

// configKeys are the keys a config file may hold.
var configKeys = map[string]bool{"api_key": true, "url": true}

// defaultConfigPath is <user config dir>/eyalsec/config, for example
// ~/.config/eyalsec/config on Linux. EYALSEC_CONFIG overrides it.
func defaultConfigPath(env func(string) string) (string, error) {
	if p := env("EYALSEC_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := userConfigDir(env)
	if err != nil {
		return "", fmt.Errorf("cannot find your config directory (%v); set EYALSEC_CONFIG to a file path", err)
	}
	return filepath.Join(dir, "eyalsec", "config"), nil
}

// userConfigDir is os.UserConfigDir, but reading the environment through env
// so tests can point it anywhere.
func userConfigDir(env func(string) string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		if d := env("AppData"); d != "" {
			return d, nil
		}
		return "", errors.New("%AppData% is not set")
	case "darwin", "ios":
		if h := env("HOME"); h != "" {
			return filepath.Join(h, "Library", "Application Support"), nil
		}
		return "", errors.New("$HOME is not set")
	default:
		if d := env("XDG_CONFIG_HOME"); d != "" && filepath.IsAbs(d) {
			return d, nil
		}
		if h := env("HOME"); h != "" {
			return filepath.Join(h, ".config"), nil
		}
		return "", errors.New("neither $XDG_CONFIG_HOME nor $HOME is set")
	}
}

// readConfigFile parses a config file of `key = value` lines. Blank lines and
// lines starting with # are ignored. A missing file is an empty config.
func readConfigFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return nil, fmt.Errorf("%s line %d: expected key = value", path, line)
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if !configKeys[k] {
			return nil, fmt.Errorf("%s line %d: unknown key %q (known: api_key, url)", path, line, k)
		}
		out[k] = v
	}
	return out, sc.Err()
}

// writeConfigFile writes values to path with owner-only permissions.
func writeConfigFile(path string, values map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	keys := make([]string, 0, len(values))
	for k, v := range values {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# eyalsec-cli configuration. Keep this file private: it holds your API key.\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %s\n", k, values[k])
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// configTooOpen reports whether a config file holding a key can be read by
// other users (Unix only; Windows permissions are not mode bits).
func configTooOpen(path string) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return st.Mode().Perm()&0o077 != 0
}

// loadConfig resolves the API key and URL. Precedence, highest first: the
// --url flag, the environment (EYALSEC_API_KEY, EYALSEC_URL), the config file.
func loadConfig(env func(string) string, path, urlFlag string) (Config, error) {
	file, err := readConfigFile(path)
	if err != nil {
		return Config{}, err
	}
	c := Config{}
	switch {
	case env("EYALSEC_API_KEY") != "":
		c.APIKey, c.KeySource = strings.TrimSpace(env("EYALSEC_API_KEY")), "EYALSEC_API_KEY"
	case file["api_key"] != "":
		c.APIKey, c.KeySource = file["api_key"], path
	}
	switch {
	case urlFlag != "":
		c.URL, c.URLSource = urlFlag, "--url"
	case env("EYALSEC_URL") != "":
		c.URL, c.URLSource = env("EYALSEC_URL"), "EYALSEC_URL"
	case file["url"] != "":
		c.URL, c.URLSource = file["url"], path
	default:
		c.URL, c.URLSource = "https://eyalsec.com", "default"
	}
	return c, nil
}

// maskKey shows enough of a key to recognise it and no more.
func maskKey(k string) string {
	if len(k) <= 12 {
		return strings.Repeat("*", len(k))
	}
	return k[:8] + "..."
}
