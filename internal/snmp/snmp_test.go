package snmp

import (
	"testing"
	"time"
)

func TestResolvePort(t *testing.T) {
	rows := map[int]*ifRow{
		1:  {ifIndex: 1, name: "GigabitEthernet6/2", descr: "GigabitEthernet6/2"},
		2:  {ifIndex: 2, name: "TenGigabitEthernet1/0/1", descr: "TenGigabitEthernet1/0/1"},
		3:  {ifIndex: 3, name: "GigabitEthernet0/0/2", descr: "GigabitEthernet0/0/2"},
		10: {ifIndex: 10, name: "Vlan10", descr: "Vlan10"},
	}

	tests := []struct {
		label   string
		wantIdx int
		wantOK  bool
	}{
		{"GigabitEthernet6/2", 1, true},
		{"gigabitethernet6/2", 1, true},
		{"Gi6/2", 1, true},
		{"6/2", 1, true},
		{"Te1/0/1", 2, true},
		{"1/0/1", 2, true},
		{"GE0/0/2", 3, true},
		{"Vlan10", 10, true},
		{"9/9", 0, false},
		{"", 0, false},
	}
	// Huawei digit-leading short forms must resolve against long/other forms.
	rows[20] = &ifRow{ifIndex: 20, name: "100GE1/0/5", descr: "100GE1/0/5"}
	if idx, ok := resolvePort(rows, "100GE1/0/5"); !ok || idx != 20 {
		t.Errorf("resolvePort(100GE1/0/5) = (%d,%v), want (20,true)", idx, ok)
	}
	if idx, ok := resolvePort(rows, "1/5"); !ok || idx != 20 {
		t.Errorf("resolvePort(1/5) should match 100GE1/0/5 tuple: (%d,%v)", idx, ok)
	}
	for _, tt := range tests {
		idx, ok := resolvePort(rows, tt.label)
		if ok != tt.wantOK || (ok && idx != tt.wantIdx) {
			t.Errorf("resolvePort(%q) = (%d,%v), want (%d,%v)", tt.label, idx, ok, tt.wantIdx, tt.wantOK)
		}
	}
}

func TestResolvePortAmbiguousTuple(t *testing.T) {
	rows := map[int]*ifRow{
		1: {ifIndex: 1, name: "GigabitEthernet1/1", descr: "GigabitEthernet1/1"},
		2: {ifIndex: 2, name: "TenGigabitEthernet1/1", descr: "TenGigabitEthernet1/1"},
	}
	if idx, ok := resolvePort(rows, "1/1"); ok {
		t.Errorf("expected ambiguous bare tuple to fail, got idx=%d", idx)
	}
	if idx, ok := resolvePort(rows, "Te1/1"); !ok || idx != 2 {
		t.Errorf("qualified label should disambiguate: got (%d,%v)", idx, ok)
	}
}

func TestStatusDurationSeconds(t *testing.T) {
	tests := []struct {
		sysUpTime  uint32
		lastChange uint32
		wantSecs   int64
		wantOK     bool
	}{
		{sysUpTime: 100000, lastChange: 10000, wantSecs: 900, wantOK: true},
		{sysUpTime: 100000, lastChange: 0, wantOK: false},
		{sysUpTime: 5000, lastChange: 10000, wantOK: false},
		{sysUpTime: 10000, lastChange: 10000, wantSecs: 0, wantOK: true},
	}
	for _, tt := range tests {
		secs, ok := statusDurationSeconds(tt.sysUpTime, tt.lastChange)
		if ok != tt.wantOK || (ok && secs != tt.wantSecs) {
			t.Errorf("statusDurationSeconds(%d,%d) = (%d,%v), want (%d,%v)",
				tt.sysUpTime, tt.lastChange, secs, ok, tt.wantSecs, tt.wantOK)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	// 1d 0h 54m 2s = 86400 + 3242 = 89642
	if got := formatDuration(89642); got != "1d 0h 54m 2s" {
		t.Errorf("formatDuration = %q, want %q", got, "1d 0h 54m 2s")
	}
}

func TestBuildPortStatusDirectionAndDuplex(t *testing.T) {
	pollTime := time.Date(2026, 7, 2, 18, 59, 0, 0, time.UTC)
	r := &ifRow{
		ifIndex:     602,
		name:        "GigabitEthernet6/2",
		alias:       "uplink",
		adminStatus: 1,
		operStatus:  2,
		lastChange:  10000,
		highSpeed:   1000,
		hcIn:        3_000_000,
		hcOut:       7_000_000,
		inErrors:    5,
		outErrors:   9,
		duplex:      3,
		hasDuplex:   true,
	}

	got := buildPortStatus(r, "TAF-SJE-SKODJE-AR3", 100000, pollTime, false)
	if got.OperStatus != "down" || got.AdminStatus != "up" {
		t.Fatalf("status names: admin=%q oper=%q", got.AdminStatus, got.OperStatus)
	}
	if got.Duplex != "full" {
		t.Fatalf("duplex = %q, want full", got.Duplex)
	}
	if got.SpeedMbps != 1000 {
		t.Fatalf("speed = %d, want 1000", got.SpeedMbps)
	}
	if got.DsBytes != 7_000_000 || got.UsBytes != 3_000_000 {
		t.Fatalf("Ds/Us bytes = %d/%d, want 7000000/3000000", got.DsBytes, got.UsBytes)
	}
	if got.DsPacketErrors != 9 || got.UsPacketErrors != 5 {
		t.Fatalf("Ds/Us errors = %d/%d, want 9/5", got.DsPacketErrors, got.UsPacketErrors)
	}
	if got.DsDataMB != 7.0 || got.UsDataMB != 3.0 {
		t.Fatalf("Ds/Us MB = %v/%v, want 7/3", got.DsDataMB, got.UsDataMB)
	}
	if got.StatusDuration != "0d 0h 15m 0s" {
		t.Fatalf("duration = %q, want 0d 0h 15m 0s", got.StatusDuration)
	}

	rev := buildPortStatus(r, "sw", 100000, pollTime, true)
	if rev.DsBytes != 3_000_000 || rev.UsBytes != 7_000_000 {
		t.Fatalf("reversed Ds/Us bytes = %d/%d, want 3000000/7000000", rev.DsBytes, rev.UsBytes)
	}
}

func TestTrailingIndex(t *testing.T) {
	tests := []struct {
		name    string
		wantIdx int
		wantOK  bool
	}{
		{".1.3.6.1.2.1.2.2.1.8.602", 602, true},
		{"1.3.6.1.2.1.31.1.1.1.6.10007", 10007, true},
		{"1.3.6.1.2.1.2.2.1.8", 8, true},
		{"", 0, false},
	}
	for _, tt := range tests {
		idx, ok := trailingIndex(tt.name)
		if ok != tt.wantOK || (ok && idx != tt.wantIdx) {
			t.Errorf("trailingIndex(%q) = (%d,%v), want (%d,%v)", tt.name, idx, ok, tt.wantIdx, tt.wantOK)
		}
	}
}
