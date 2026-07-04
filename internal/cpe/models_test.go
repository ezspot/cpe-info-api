package cpe

import "testing"

func TestCommandProfileForModel(t *testing.T) {
	tests := []struct {
		model       string
		wantProfile string
	}{
		{"VANTIVA", "vantiva-openwrt-v1"},
		{"VANTIVA_F1X", "vantiva-openwrt-v1"},
		{"FO1", "vantiva-openwrt-v1"},
		{"F1X", "vantiva-openwrt-v1"},
		{"EWA1331", "vantiva-openwrt-v1"},
		{"ewa1331", "vantiva-openwrt-v1"},
		{"AX7501", "zyxel-ax-v1"},
		{"EX5401", "zyxel-v1"},
		{"EX5601", "zyxel-v1"},
		{"VMG8825", "zyxel-v1"},
		{"P2812", "zyxel-v1"},
		{"EMG2812AC", "zyxel-v1"},
		{"FMG3542", "zyxel-v1"},
		{"", "zyxel-v1"},
	}
	for _, tt := range tests {
		if got := commandProfileForModel(tt.model); got.name != tt.wantProfile {
			t.Errorf("commandProfileForModel(%q) = %q, want %q", tt.model, got.name, tt.wantProfile)
		}
	}
}

func TestDefaultPortForModel(t *testing.T) {
	tests := []struct {
		model    string
		wantPort int
	}{
		{"VANTIVA", 60022},
		{"VANTIVA_F1X", 60022},
		{"FO1", 60022},
		{"EWA1331", 60022},
		{"EX5401", 22},
		{"", 22},
	}
	for _, tt := range tests {
		if got := DefaultPortForModel(tt.model); got != tt.wantPort {
			t.Errorf("DefaultPortForModel(%q) = %d, want %d", tt.model, got, tt.wantPort)
		}
	}
}

func TestVantivaActionDefinitions(t *testing.T) {
	wantActions := map[string]string{
		"reboot":        "reboot",
		"semi_reset":    "rtfd --soft",
		"factory_reset": "rtfd",
	}
	for action, wantCmd := range wantActions {
		def, ok := resolveActionDefinition("vantiva-openwrt-v1", action)
		if !ok {
			t.Errorf("action %q not defined for vantiva-openwrt-v1", action)
			continue
		}
		if def.command != wantCmd {
			t.Errorf("action %q command = %q, want %q", action, def.command, wantCmd)
		}
	}
}
