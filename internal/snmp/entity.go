package snmp

import (
	"math"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
)

type entity struct {
	class       int
	containedIn int
	name        string
	descr       string
}

func detectVendor(client *gosnmp.GoSNMP) string {
	packet, err := client.Get([]string{oidSysObjectID})
	if err != nil || len(packet.Variables) == 0 {
		return ""
	}
	oid := strings.TrimPrefix(pduString(packet.Variables[0]), ".")
	switch {
	case strings.HasPrefix(oid, strings.TrimPrefix(sysObjectIDHuawei, ".")):
		return "huawei"
	case strings.HasPrefix(oid, strings.TrimPrefix(sysObjectIDCisco, ".")):
		return "cisco"
	default:
		return ""
	}
}

// aliasMap maps entPhysicalIndex -> ifIndex via entAliasMappingIdentifier, whose
// value is an OID ending in the ifIndex.
func aliasMap(client *gosnmp.GoSNMP) map[int]int {
	out := make(map[int]int)
	pdus, err := client.BulkWalkAll(colEntAliasMapping)
	if err != nil {
		return out
	}
	for i := range pdus {
		pdu := pdus[i]
		if isException(pdu) {
			continue
		}
		physIdx, ok := secondLastIndex(pdu.Name)
		if !ok {
			continue
		}
		ifIdx, ok := trailingIndex(pduString(pdu))
		if !ok || ifIdx == 0 {
			continue
		}
		out[physIdx] = ifIdx
	}
	return out
}

func readEntities(client *gosnmp.GoSNMP) map[int]*entity {
	entities := make(map[int]*entity)
	ent := func(idx int) *entity {
		e, ok := entities[idx]
		if !ok {
			e = &entity{}
			entities[idx] = e
		}
		return e
	}

	columns := []struct {
		oid   string
		apply func(e *entity, pdu gosnmp.SnmpPDU)
	}{
		{colEntPhysicalClass, func(e *entity, p gosnmp.SnmpPDU) { e.class = int(pduUint(p)) }},
		{colEntPhysicalContainedIn, func(e *entity, p gosnmp.SnmpPDU) { e.containedIn = int(pduUint(p)) }},
		{colEntPhysicalName, func(e *entity, p gosnmp.SnmpPDU) { e.name = pduString(p) }},
		{colEntPhysicalDescr, func(e *entity, p gosnmp.SnmpPDU) { e.descr = pduString(p) }},
	}
	for _, col := range columns {
		pdus, err := client.BulkWalkAll(col.oid)
		if err != nil {
			continue
		}
		for i := range pdus {
			pdu := pdus[i]
			if isException(pdu) {
				continue
			}
			if idx, ok := trailingIndex(pdu.Name); ok {
				col.apply(ent(idx), pdu)
			}
		}
	}
	return entities
}

// resolveSensorIfIndex climbs the ENTITY-MIB containment tree from a sensor to its
// owning port/module and resolves that to an ifIndex via the alias map or a name match.
func resolveSensorIfIndex(sensorIdx int, entities map[int]*entity, alias map[int]int, nameToIf map[string]int) (int, bool) {
	p := sensorIdx
	for hops := 0; p != 0 && hops < 16; hops++ {
		e := entities[p]
		if e == nil {
			return 0, false
		}
		if e.class == entClassPort || e.class == entClassModule {
			if ifIdx, ok := alias[p]; ok {
				return ifIdx, true
			}
			if ifIdx, ok := nameToIf[e.name]; ok {
				return ifIdx, true
			}
		}
		p = e.containedIn
	}
	return 0, false
}

func scaleExponent(scale int) int {
	// EntitySensorDataScale enum -> power-of-ten exponent.
	switch scale {
	case 1:
		return -24
	case 2:
		return -21
	case 3:
		return -18
	case 4:
		return -15
	case 5:
		return -12
	case 6:
		return -9
	case 7:
		return -6
	case 8:
		return -3
	case 9:
		return 0
	case 10:
		return 3
	case 11:
		return 6
	case 12:
		return 9
	default:
		return 0
	}
}

// decodeSensor applies EntitySensor scale + precision: value * 10^scaleExp / 10^precision.
// precision is -8..9; negative values multiply (Pow10 handles the sign), 0 is a no-op.
func decodeSensor(value int64, scale, precision int) float64 {
	v := float64(value) * math.Pow10(scaleExponent(scale))
	return v / math.Pow10(precision)
}

func wattsToDBm(watts float64) (float64, bool) {
	mw := watts * 1000
	if mw <= 0 {
		return 0, false
	}
	return 10 * math.Log10(mw), true
}

func secondLastIndex(name string) (int, bool) {
	name = strings.TrimRight(name, ".")
	last := strings.LastIndex(name, ".")
	if last < 0 {
		return 0, false
	}
	prev := strings.LastIndex(name[:last], ".")
	if prev < 0 {
		return 0, false
	}
	idx, err := strconv.Atoi(name[prev+1 : last])
	if err != nil {
		return 0, false
	}
	return idx, true
}

func floatPtr(v float64) *float64 { return &v }
