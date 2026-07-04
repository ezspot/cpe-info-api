package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDotEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := `# comment
ADDR=:9999
export CPE_API_KEY="quoted-secret"
CPE_ALLOWED_TARGET_CIDRS="10.0.0.0/8,192.168.1.1/32"
PRESET=fromfile

BLANKABOVE=ok
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PRESET", "fromenv") // already set -> must NOT be overridden
	for _, k := range []string{"ADDR", "CPE_API_KEY", "CPE_ALLOWED_TARGET_CIDRS", "BLANKABOVE"} {
		os.Unsetenv(k)
	}

	if err := LoadDotEnv(path); err != nil {
		t.Fatalf("LoadDotEnv: %v", err)
	}

	checks := map[string]string{
		"ADDR":                     ":9999",
		"CPE_API_KEY":              "quoted-secret",
		"CPE_ALLOWED_TARGET_CIDRS": "10.0.0.0/8,192.168.1.1/32",
		"BLANKABOVE":               "ok",
		"PRESET":                   "fromenv",
	}
	for k, want := range checks {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestLoadDotEnvMissingFileIsOK(t *testing.T) {
	if err := LoadDotEnv(filepath.Join(t.TempDir(), "nope.env")); err != nil {
		t.Fatalf("missing file should be nil, got %v", err)
	}
}
