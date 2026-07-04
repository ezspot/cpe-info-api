package snmp

import (
	"math"
	"testing"
)

func TestDecodeSensor(t *testing.T) {
	tests := []struct {
		name      string
		value     int64
		scale     int
		precision int
		want      float64
	}{
		{"deci-dBm rx", -35, 9, 1, -3.5},
		{"deci-dBm tx", 15, 9, 1, 1.5},
		{"milli volts", 3300, 8, 0, 3.3},
		{"units volts precision3", 3300, 9, 3, 3.3},
		{"whole celsius", 47, 9, 0, 47},
		{"precision sentinel treated as 0 by caller", -354, 9, 0, -354},
		{"legit -12.7 dBm not a sentinel", -127, 9, 1, -12.7},
		{"negative precision multiplies", 15, 9, -1, 150},
		{"negative precision x2", 3, 9, -2, 300},
	}
	for _, tt := range tests {
		got := decodeSensor(tt.value, tt.scale, tt.precision)
		if math.Abs(got-tt.want) > 1e-9 {
			t.Errorf("%s: decodeSensor(%d,%d,%d) = %v, want %v", tt.name, tt.value, tt.scale, tt.precision, got, tt.want)
		}
	}
}

func TestWattsToDBm(t *testing.T) {
	// 0.302 mW -> ~ -5.2 dBm
	got, ok := wattsToDBm(302e-6)
	if !ok || math.Abs(got-(-5.2)) > 0.1 {
		t.Errorf("wattsToDBm(302uW) = %v (ok=%v), want ~-5.2", got, ok)
	}
	if _, ok := wattsToDBm(0); ok {
		t.Errorf("wattsToDBm(0) should be invalid")
	}
	if _, ok := wattsToDBm(-1); ok {
		t.Errorf("wattsToDBm(negative) should be invalid")
	}
}

func TestAssignOpticalPower(t *testing.T) {
	rx := &Optics{}
	assignOpticalPower(rx, "Te1/1/1 Receive Power Sensor", -8.0)
	if rx.RxPowerDbm == nil || *rx.RxPowerDbm != -8.0 || rx.TxPowerDbm != nil {
		t.Fatalf("receive routing failed: %+v", rx)
	}

	tx := &Optics{}
	assignOpticalPower(tx, "GigabitEthernet6/2 Transmit Power Sensor", -4.8)
	if tx.TxPowerDbm == nil || *tx.TxPowerDbm != -4.8 || tx.RxPowerDbm != nil {
		t.Fatalf("transmit routing failed: %+v", tx)
	}

	short := &Optics{}
	assignOpticalPower(short, "Rx Power", -2.0)
	if short.RxPowerDbm == nil {
		t.Fatalf("short rx label failed: %+v", short)
	}

	// Directionless label: keep the reading rather than dropping it.
	fallback := &Optics{}
	assignOpticalPower(fallback, "Optical Power", -6.0)
	if fallback.RxPowerDbm == nil || *fallback.RxPowerDbm != -6.0 {
		t.Fatalf("directionless power should fall back to Rx: %+v", fallback)
	}
}

func TestSecondLastIndex(t *testing.T) {
	// entAliasMappingIdentifier.<physIdx>.<logical>
	idx, ok := secondLastIndex("1.3.6.1.2.1.47.1.3.2.1.2.67141710.0")
	if !ok || idx != 67141710 {
		t.Fatalf("secondLastIndex = (%d,%v), want 67141710", idx, ok)
	}
}

func TestScaleExponent(t *testing.T) {
	cases := map[int]int{6: -9, 7: -6, 8: -3, 9: 0, 10: 3, 99: 0}
	for scale, want := range cases {
		if got := scaleExponent(scale); got != want {
			t.Errorf("scaleExponent(%d) = %d, want %d", scale, got, want)
		}
	}
}
