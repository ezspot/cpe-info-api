package snmp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePortGroup(t *testing.T) {
	tests := []struct {
		in        string
		wantVend  string
		wantKey   string
		wantIface string
		wantErr   bool
	}{
		{"TAFAALLERSTADAR3S003P20", "cisco", "tafaallerstadar3", "3/20", false},
		{"tafaallerstadar3s003p20", "cisco", "tafaallerstadar3", "3/20", false},
		{"TAFAALLERSTADAR3S002P03", "cisco", "tafaallerstadar3", "2/3", false},
		{"NVFAALLERSTADAR1S001P05", "huawei", "nvfaallerstadar1", "1/5", false},
		{"TAFHARBRATTVAGAR2S010P48", "cisco", "tafharbrattvagar2", "10/48", false},
		{"GARBAGE", "", "", "", true},
		{"TAFAALLERSTADAR3", "", "", "", true},
	}
	for _, tt := range tests {
		pg, err := ParsePortGroup(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParsePortGroup(%q) expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortGroup(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if pg.Vendor != tt.wantVend || pg.SwitchKey != tt.wantKey || pg.Interface != tt.wantIface {
			t.Errorf("ParsePortGroup(%q) = vendor %q key %q iface %q, want %q %q %q",
				tt.in, pg.Vendor, pg.SwitchKey, pg.Interface, tt.wantVend, tt.wantKey, tt.wantIface)
		}
	}
}

func TestHostResolver(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	content := `## AR ##
10.160.25.71 taf-aal-lerstad-ar1
10.160.25.72 taf-aal-lerstad-ar2
10.160.25.6  taf-har-brattvag-ar1
# comment line
badline-without-ip
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := NewHostResolver(path)
	if err != nil {
		t.Fatalf("NewHostResolver: %v", err)
	}

	pg, _ := ParsePortGroup("TAFAALLERSTADAR2S003P20")
	ip, ok := r.Resolve(pg.SwitchKey)
	if !ok || ip != "10.160.25.72" {
		t.Fatalf("Resolve(%q) = %q,%v, want 10.160.25.72", pg.SwitchKey, ip, ok)
	}

	if _, ok := r.Resolve("tafaallerstadar9"); ok {
		t.Fatalf("unknown switch key should not resolve")
	}
}

func TestHostResolverRejectsCollision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	// Two distinct hostnames normalize to the same key but different IPs.
	content := "10.0.0.1 taf-aal-lerstad-ar1\n10.0.0.2 tafaal-lerstadar1\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHostResolver(path); err == nil {
		t.Fatalf("expected error on normalized-key collision to different IPs")
	}
}

func TestTupleCandidates(t *testing.T) {
	two := tupleCandidates("3/20")
	if !two["3/20"] || !two["3/0/20"] {
		t.Fatalf("2-tuple should expand to 3-tuple: %v", two)
	}
	three := tupleCandidates("3/0/20")
	if !three["3/0/20"] || !three["3/20"] {
		t.Fatalf("3-tuple with /0/ should collapse to 2-tuple: %v", three)
	}
}

func TestResolvePortTupleExpansion(t *testing.T) {
	rows := map[int]*ifRow{
		1: {ifIndex: 1, name: "GigabitEthernet3/0/20", descr: "GigabitEthernet3/0/20"},
	}
	// port group yields "3/20"; must match the stacked 3-tuple name.
	if idx, ok := resolvePort(rows, "3/20"); !ok || idx != 1 {
		t.Fatalf("resolvePort(3/20) = (%d,%v), want (1,true)", idx, ok)
	}
}
