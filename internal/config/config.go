package config

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// LoadDotEnv loads KEY=VALUE lines from path into the process environment without
// overriding variables already set (so real env / container config wins). A
// missing file is not an error, so production can rely purely on real env vars.
func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if err := os.Setenv(key, val); err != nil {
			return err
		}
	}
	return scanner.Err()
}

type Config struct {
	Addr     string
	LogLevel slog.Level

	APIKey string

	AllowedTargetCIDRs []*net.IPNet
	Concurrency        int

	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration

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

	SNMP            SNMPConfig
	SwitchHostsFile string
}

type SNMPConfig struct {
	Port               int
	Version            string
	Community          string
	V3User             string
	V3Level            string
	V3AuthProtocol     string
	V3AuthPassphrase   string
	V3PrivProtocol     string
	V3PrivPassphrase   string
	Timeout            time.Duration
	RequestTimeout     time.Duration
	Retries            int
	MaxRepetitions     uint32
	AllowedTargetCIDRs []*net.IPNet
}

// Configured reports whether SNMP polling credentials are present.
func (s SNMPConfig) Configured() bool {
	return s.Community != "" || s.V3User != ""
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

		ReadHeaderTimeout: envDur("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
		ReadTimeout:       envDur("HTTP_READ_TIMEOUT", 20*time.Second),
		WriteTimeout:      envDur("HTTP_WRITE_TIMEOUT", 60*time.Second),
		IdleTimeout:       envDur("HTTP_IDLE_TIMEOUT", 60*time.Second),

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

	if cfg.WriteTimeout <= 0 {
		return Config{}, fmt.Errorf("HTTP_WRITE_TIMEOUT must be > 0")
	}
	// The CPE collect/action poll runs synchronously before the response is
	// written, so its budget must fit inside the server write deadline.
	if cfg.RequestTimeout >= cfg.WriteTimeout {
		return Config{}, fmt.Errorf("CPE_REQUEST_TIMEOUT (%s) must be less than HTTP_WRITE_TIMEOUT (%s)", cfg.RequestTimeout, cfg.WriteTimeout)
	}

	snmp, err := loadSNMP(cfg.AllowedTargetCIDRs, cfg.WriteTimeout)
	if err != nil {
		return Config{}, err
	}
	cfg.SNMP = snmp
	cfg.SwitchHostsFile = envStr("SWITCH_HOSTS_FILE", "")

	return cfg, nil
}

func loadSNMP(defaultCIDRs []*net.IPNet, writeTimeout time.Duration) (SNMPConfig, error) {
	snmp := SNMPConfig{
		Port:             envInt("SNMP_PORT", 161),
		Version:          strings.ToLower(envStr("SNMP_VERSION", "2c")),
		Community:        envStr("SNMP_COMMUNITY", ""),
		V3User:           envStr("SNMP_V3_USER", ""),
		V3Level:          strings.ToLower(envStr("SNMP_V3_LEVEL", "authPriv")),
		V3AuthProtocol:   strings.ToUpper(envStr("SNMP_V3_AUTH_PROTOCOL", "SHA")),
		V3AuthPassphrase: envStr("SNMP_V3_AUTH_PASS", ""),
		V3PrivProtocol:   strings.ToUpper(envStr("SNMP_V3_PRIV_PROTOCOL", "AES")),
		V3PrivPassphrase: envStr("SNMP_V3_PRIV_PASS", ""),
		Timeout:          envDur("SNMP_TIMEOUT", 5*time.Second),
		RequestTimeout:   envDur("SNMP_REQUEST_TIMEOUT", 30*time.Second),
		Retries:          envInt("SNMP_RETRIES", 2),
		MaxRepetitions:   uint32(envInt("SNMP_MAX_REPETITIONS", 20)),
	}

	allowedCSV := envStr("SNMP_ALLOWED_TARGET_CIDRS", "")
	if allowedCSV == "" {
		snmp.AllowedTargetCIDRs = defaultCIDRs
	} else {
		allowed, err := parseCIDRs(allowedCSV)
		if err != nil {
			return SNMPConfig{}, err
		}
		snmp.AllowedTargetCIDRs = allowed
	}

	if !snmp.Configured() {
		return snmp, nil
	}

	switch snmp.Version {
	case "2c", "3":
	default:
		return SNMPConfig{}, fmt.Errorf("SNMP_VERSION must be 2c or 3")
	}
	if snmp.Version == "2c" && snmp.Community == "" {
		return SNMPConfig{}, fmt.Errorf("SNMP_COMMUNITY is required for SNMP_VERSION=2c")
	}
	if snmp.Version == "3" && snmp.V3User == "" {
		return SNMPConfig{}, fmt.Errorf("SNMP_V3_USER is required for SNMP_VERSION=3")
	}
	if snmp.Port < 1 || snmp.Port > 65535 {
		return SNMPConfig{}, fmt.Errorf("SNMP_PORT must be in range 1..65535")
	}
	if snmp.Timeout <= 0 || snmp.RequestTimeout <= 0 {
		return SNMPConfig{}, fmt.Errorf("SNMP timeouts must be > 0")
	}
	// The poll runs synchronously before the HTTP response is written, so its
	// overall budget must fit inside the server write deadline.
	if snmp.RequestTimeout >= writeTimeout {
		return SNMPConfig{}, fmt.Errorf("SNMP_REQUEST_TIMEOUT (%s) must be less than HTTP_WRITE_TIMEOUT (%s)", snmp.RequestTimeout, writeTimeout)
	}

	return snmp, nil
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
