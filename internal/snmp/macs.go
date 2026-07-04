package snmp

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// enrichMACs attaches learned MAC addresses (with VLAN) to the selected
// interfaces via Q-BRIDGE dot1qTpFdbTable. Best-effort: failures leave macs unset.
func (c *Collector) enrichMACs(client *gosnmp.GoSNMP, rows map[int]*ifRow) {
	if len(rows) == 0 {
		return
	}

	basePortToIf := walkBasePortIfIndex(client)
	if len(basePortToIf) == 0 {
		return
	}

	statusBySuffix := make(map[string]int64)
	statusKnown := false
	if pdus, err := client.BulkWalkAll(colDot1qTpFdbStatus); err == nil && len(pdus) > 0 {
		statusKnown = true
		for i := range pdus {
			if isException(pdus[i]) {
				continue
			}
			if suffix, ok := columnSuffix(pdus[i].Name, colDot1qTpFdbStatus); ok {
				statusBySuffix[suffix] = pduInt(pdus[i])
			}
		}
	}

	pdus, err := client.BulkWalkAll(colDot1qTpFdbPort)
	if err != nil {
		return
	}
	for i := range pdus {
		pdu := pdus[i]
		if isException(pdu) {
			continue
		}
		basePort := int(pduInt(pdu))
		if basePort == 0 {
			continue
		}
		ifIdx, ok := basePortToIf[basePort]
		if !ok {
			continue
		}
		r, wanted := rows[ifIdx]
		if !wanted {
			continue
		}
		if len(r.macs) >= maxMACsPerPort {
			continue
		}
		suffix, ok := columnSuffix(pdu.Name, colDot1qTpFdbPort)
		if !ok {
			continue
		}
		// Fail closed when status is known: only report confirmed-learned MACs.
		if statusKnown {
			if status, ok := statusBySuffix[suffix]; !ok || status != fdbStatusLearned {
				continue
			}
		}
		vlan, mac, ok := parseFdbSuffix(suffix)
		if !ok {
			continue
		}
		r.macs = append(r.macs, MACEntry{MAC: mac, VLAN: vlan})
	}
}

func walkBasePortIfIndex(client *gosnmp.GoSNMP) map[int]int {
	out := make(map[int]int)
	pdus, err := client.BulkWalkAll(colDot1dBasePortIfIndex)
	if err != nil {
		return out
	}
	for i := range pdus {
		if isException(pdus[i]) {
			continue
		}
		if basePort, ok := trailingIndex(pdus[i].Name); ok {
			out[basePort] = int(pduInt(pdus[i]))
		}
	}
	return out
}

func columnSuffix(name, base string) (string, bool) {
	name = strings.TrimPrefix(name, ".")
	base = strings.TrimPrefix(base, ".")
	if !strings.HasPrefix(name, base+".") {
		return "", false
	}
	return name[len(base)+1:], true
}

// parseFdbSuffix decodes "<fdbId>.<m1>.<m2>.<m3>.<m4>.<m5>.<m6>" (optionally with
// a leading MAC length byte "6") into a VLAN and colon MAC string.
func parseFdbSuffix(suffix string) (int, string, bool) {
	parts := strings.Split(suffix, ".")
	if len(parts) < 7 {
		return 0, "", false
	}
	fdbID, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", false
	}
	octets := parts[1:]
	if len(octets) == 7 && octets[0] == "6" {
		octets = octets[1:]
	}
	if len(octets) != 6 {
		return 0, "", false
	}
	b := make([]byte, 6)
	for i, o := range octets {
		n, err := strconv.Atoi(o)
		if err != nil || n < 0 || n > 255 {
			return 0, "", false
		}
		b[i] = byte(n)
	}
	mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
	return fdbID, mac, true
}
