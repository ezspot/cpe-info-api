package snmp

import (
	"strings"

	"github.com/gosnmp/gosnmp"
)

// enrichOptics attaches transceiver DDM/DOM readings to the selected interfaces.
// Best-effort: any failure leaves the interface data intact and optics unset.
func (c *Collector) enrichOptics(client *gosnmp.GoSNMP, rows map[int]*ifRow) {
	if len(rows) == 0 {
		return
	}

	vendor := detectVendor(client)
	var optics map[int]*Optics
	switch vendor {
	case "cisco":
		optics = c.readCiscoOptics(client, rows)
	case "huawei":
		optics = c.readHuaweiOptics(client)
	default:
		return
	}

	for idx, o := range optics {
		if r, ok := rows[idx]; ok && o != nil && !o.empty() {
			r.optics = o
		}
	}
}

func (o *Optics) empty() bool {
	return o.RxPowerDbm == nil && o.TxPowerDbm == nil && o.TemperatureC == nil &&
		o.VoltageV == nil && o.CurrentMA == nil
}

func (c *Collector) readCiscoOptics(client *gosnmp.GoSNMP, rows map[int]*ifRow) map[int]*Optics {
	types := walkIntColumn(client, colCiscoSensorType)
	if len(types) == 0 {
		return nil
	}
	scales := walkIntColumn(client, colCiscoSensorScale)
	precisions := walkIntColumn(client, colCiscoSensorPrecision)
	values := walkIntColumn(client, colCiscoSensorValue)
	statuses := walkIntColumn(client, colCiscoSensorStatus)

	entities := readEntities(client)
	alias := aliasMap(client)
	nameToIf := interfaceNameIndex(rows)

	out := make(map[int]*Optics)
	opticsFor := func(ifIdx int) *Optics {
		o, ok := out[ifIdx]
		if !ok {
			o = &Optics{}
			out[ifIdx] = o
		}
		return o
	}

	for sensorIdx, sensorType := range types {
		if status, ok := statuses[sensorIdx]; ok && status != ciscoSensorStatusOK {
			continue
		}
		raw, ok := values[sensorIdx]
		if !ok {
			continue
		}
		// Require scale+precision so a partial walk can't mis-scale a reading;
		// -127 is NOT treated as a sentinel (it is a valid -12.7 dBm at precision 1).
		scale, ok := scales[sensorIdx]
		if !ok {
			continue
		}
		precRaw, ok := precisions[sensorIdx]
		if !ok {
			continue
		}
		ifIdx, ok := resolveSensorIfIndex(sensorIdx, entities, alias, nameToIf)
		if !ok {
			continue
		}
		if _, wanted := rows[ifIdx]; !wanted {
			continue
		}

		precision := int(precRaw)
		if precision == ciscoPrecisionSentinel {
			precision = 0
		}
		decoded := decodeSensor(raw, int(scale), precision)
		label := entities[sensorIdx]
		name := ""
		if label != nil {
			name = label.name + " " + label.descr
		}

		switch int(sensorType) {
		case ciscoSensorDBm:
			assignOpticalPower(opticsFor(ifIdx), name, decoded)
		case ciscoSensorWatts:
			if dbm, ok := wattsToDBm(decoded); ok {
				assignOpticalPower(opticsFor(ifIdx), name, dbm)
			}
		case ciscoSensorCelsius:
			opticsFor(ifIdx).TemperatureC = floatPtr(decoded)
		case ciscoSensorVoltsDC:
			opticsFor(ifIdx).VoltageV = floatPtr(decoded)
		case ciscoSensorAmperes:
			opticsFor(ifIdx).CurrentMA = floatPtr(decoded * 1000)
		}
	}
	return out
}

func (c *Collector) readHuaweiOptics(client *gosnmp.GoSNMP) map[int]*Optics {
	alias := aliasMap(client)
	if len(alias) == 0 {
		return nil
	}

	rx := walkIntColumn(client, colHuaweiOpticalRxPower)
	tx := walkIntColumn(client, colHuaweiOpticalTxPower)
	temp := walkIntColumn(client, colHuaweiOpticalTemperature)
	volt := walkIntColumn(client, colHuaweiOpticalVoltage)
	bias := walkIntColumn(client, colHuaweiOpticalBiasCurrent)

	out := make(map[int]*Optics)
	set := func(physIdx int, apply func(o *Optics)) {
		ifIdx, ok := alias[physIdx]
		if !ok {
			return
		}
		o, ok := out[ifIdx]
		if !ok {
			o = &Optics{}
			out[ifIdx] = o
		}
		apply(o)
	}

	for idx, v := range rx {
		if v != huaweiOpticalSentinel {
			set(idx, func(o *Optics) { o.RxPowerDbm = floatPtr(float64(v) / 100) })
		}
	}
	for idx, v := range tx {
		if v != huaweiOpticalSentinel {
			set(idx, func(o *Optics) { o.TxPowerDbm = floatPtr(float64(v) / 100) })
		}
	}
	for idx, v := range temp {
		if v != huaweiOpticalSentinel {
			set(idx, func(o *Optics) { o.TemperatureC = floatPtr(float64(v)) })
		}
	}
	for idx, v := range volt {
		if v != huaweiOpticalSentinel {
			set(idx, func(o *Optics) { o.VoltageV = floatPtr(float64(v) / 1000) })
		}
	}
	for idx, v := range bias {
		if v != huaweiOpticalSentinel {
			set(idx, func(o *Optics) { o.CurrentMA = floatPtr(float64(v) / 1000) })
		}
	}
	return out
}

// assignOpticalPower routes a dBm reading to Rx or Tx by sensor name.
func assignOpticalPower(o *Optics, name string, dbm float64) {
	l := strings.ToLower(name)
	switch {
	case strings.Contains(l, "transmit"), strings.Contains(l, "tx"):
		o.TxPowerDbm = floatPtr(dbm)
	case strings.Contains(l, "receive"), strings.Contains(l, "rx"):
		o.RxPowerDbm = floatPtr(dbm)
	default:
		// No direction token: keep the reading rather than dropping it.
		if o.RxPowerDbm == nil {
			o.RxPowerDbm = floatPtr(dbm)
		} else if o.TxPowerDbm == nil {
			o.TxPowerDbm = floatPtr(dbm)
		}
	}
}

func interfaceNameIndex(rows map[int]*ifRow) map[string]int {
	out := make(map[string]int, len(rows)*2)
	for idx, r := range rows {
		if r.name != "" {
			out[r.name] = idx
		}
		if r.descr != "" {
			out[r.descr] = idx
		}
	}
	return out
}

func walkIntColumn(client *gosnmp.GoSNMP, column string) map[int]int64 {
	out := make(map[int]int64)
	pdus, err := client.BulkWalkAll(column)
	if err != nil {
		return out
	}
	for i := range pdus {
		pdu := pdus[i]
		if isException(pdu) {
			continue
		}
		if idx, ok := trailingIndex(pdu.Name); ok {
			out[idx] = pduInt(pdu)
		}
	}
	return out
}
