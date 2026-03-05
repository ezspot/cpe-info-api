package config

import (
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr     string
	LogLevel slog.Level

	APIKey string

	AllowedTargetCIDRs []*net.IPNet
	Concurrency        int

	RequestTimeout    time.Duration
	SSHDialTimeout    time.Duration
	SSHCommandTimeout time.Duration

	SSHUser            string
	SSHPass            string
	SSHKeyPath         string
	SSHKeyPassphrase   string
	SSHKeysDir         string
	SSHModelKeyMap     map[string]string
	VantivaCLIUser     string
	VantivaCLIPassword string
	SSHKnownHostsPath  string
	SSHInsecureHostKey bool
}

func MustLoad() Config {
	cfg, err := Load()
	if err != nil {
		log.Fatal(err)
	}
	return cfg
}

func Load() (Config, error) {
	cfg := Config{
		Addr:     envStr("ADDR", ":8080"),
		LogLevel: parseLogLevel(envStr("LOG_LEVEL", "INFO")),

		APIKey: envStr("CPE_API_KEY", ""),

		Concurrency: envInt("CPE_CONCURRENCY", 16),

		RequestTimeout:    envDur("CPE_REQUEST_TIMEOUT", 45*time.Second),
		SSHDialTimeout:    envDur("CPE_SSH_DIAL_TIMEOUT", 6*time.Second),
		SSHCommandTimeout: envDur("CPE_SSH_CMD_TIMEOUT", 12*time.Second),

		SSHUser:            envStr("CPE_SSH_USER", "root"),
		SSHPass:            envStr("CPE_SSH_PASS", ""),
		SSHKeyPath:         envStr("CPE_SSH_KEY_PATH", ""),
		SSHKeyPassphrase:   envStr("CPE_SSH_KEY_PASSPHRASE", ""),
		SSHKeysDir:         envStr("CPE_SSH_KEYS_DIR", "cpe-ssh-keys"),
		VantivaCLIUser:     envStr("VANTIVA_CPE_CLI_USER", ""),
		VantivaCLIPassword: envStr("VANTIVA_CPE_CLI_PASSWORD", ""),
		SSHKnownHostsPath:  envStr("CPE_SSH_KNOWN_HOSTS", ""),
		SSHInsecureHostKey: envBool("CPE_SSH_INSECURE_HOSTKEY", false),
	}

	modelKeyMap, err := parseModelKeyMap(envStr("CPE_SSH_MODEL_KEY_MAP", ""))
	if err != nil {
		return Config{}, err
	}
	cfg.SSHModelKeyMap = modelKeyMap

	allowedCSV := envStr("CPE_ALLOWED_TARGET_CIDRS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
	allowed, err := parseCIDRs(allowedCSV)
	if err != nil {
		return Config{}, err
	}
	cfg.AllowedTargetCIDRs = allowed

	if cfg.Concurrency < 1 || cfg.Concurrency > 1024 {
		return Config{}, fmt.Errorf("CPE_CONCURRENCY must be in range 1..1024")
	}
	if cfg.RequestTimeout <= 0 || cfg.SSHDialTimeout <= 0 || cfg.SSHCommandTimeout <= 0 {
		return Config{}, fmt.Errorf("timeouts must be > 0")
	}
	hasAnyKeySource := cfg.SSHKeyPath != "" || cfg.SSHKeysDir != "" || len(cfg.SSHModelKeyMap) > 0
	if cfg.SSHPass == "" && !hasAnyKeySource {
		return Config{}, fmt.Errorf("set CPE_SSH_PASS, CPE_SSH_KEY_PATH, or CPE_SSH_KEYS_DIR")
	}
	if !cfg.SSHInsecureHostKey && cfg.SSHKnownHostsPath == "" {
		return Config{}, fmt.Errorf("set CPE_SSH_KNOWN_HOSTS or CPE_SSH_INSECURE_HOSTKEY=true")
	}
	return cfg, nil
}

func parseCIDRs(csv string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", part, err)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("CPE_ALLOWED_TARGET_CIDRS cannot be empty")
	}
	return out, nil
}

func parseModelKeyMap(csv string) (map[string]string, error) {
	out := make(map[string]string)
	if strings.TrimSpace(csv) == "" {
		return out, nil
	}

	for _, pair := range strings.Split(csv, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid CPE_SSH_MODEL_KEY_MAP entry %q", pair)
		}
		model := strings.ToUpper(strings.TrimSpace(parts[0]))
		path := strings.TrimSpace(parts[1])
		if model == "" || path == "" {
			return nil, fmt.Errorf("invalid CPE_SSH_MODEL_KEY_MAP entry %q", pair)
		}
		out[model] = path
	}
	return out, nil
}

func parseLogLevel(v string) slog.Level {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func envStr(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envDur(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
