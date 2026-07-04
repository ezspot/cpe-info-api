package snmp

import "testing"

func TestParseFdbSuffix(t *testing.T) {
	tests := []struct {
		suffix   string
		wantVLAN int
		wantMAC  string
		wantOK   bool
	}{
		{"100.0.26.43.60.77.94", 100, "00:1a:2b:3c:4d:5e", true},
		{"10.0.27.33.196.130.15", 10, "00:1b:21:c4:82:0f", true},
		{"100.6.0.26.43.60.77.94", 100, "00:1a:2b:3c:4d:5e", true}, // leading length byte
		{"100.0.26.43", 0, "", false},                              // too short
		{"100.0.26.43.60.77.999", 0, "", false},                    // octet out of range
	}
	for _, tt := range tests {
		vlan, mac, ok := parseFdbSuffix(tt.suffix)
		if ok != tt.wantOK || (ok && (vlan != tt.wantVLAN || mac != tt.wantMAC)) {
			t.Errorf("parseFdbSuffix(%q) = (%d,%q,%v), want (%d,%q,%v)",
				tt.suffix, vlan, mac, ok, tt.wantVLAN, tt.wantMAC, tt.wantOK)
		}
	}
}

func TestColumnSuffix(t *testing.T) {
	suffix, ok := columnSuffix("1.3.6.1.2.1.17.7.1.2.2.1.2.100.0.26.43.60.77.94", colDot1qTpFdbPort)
	if !ok || suffix != "100.0.26.43.60.77.94" {
		t.Fatalf("columnSuffix = (%q,%v)", suffix, ok)
	}
	if _, ok := columnSuffix("1.3.6.1.2.1.1.5.0", colDot1qTpFdbPort); ok {
		t.Fatalf("non-matching base should return false")
	}
}
