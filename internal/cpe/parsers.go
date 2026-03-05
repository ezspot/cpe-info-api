package cpe

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func normalizeOutput(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.TrimSpace(s)
}

func parseSysAtsh(s string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key != "" {
			out[key] = value
		}
	}
	return out
}

func parseUptime(s string) *UptimeInfo {
	line := firstNonEmptyLine(s)
	out := &UptimeInfo{Raw: line}

	if len(line) >= 8 && line[2] == ':' && line[5] == ':' {
		out.ClockTime = line[:8]
	}

	if idx := strings.Index(line, " up "); idx >= 0 {
		rest := line[idx+4:]
		if lidx := strings.Index(rest, "load average:"); lidx >= 0 {
			up := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest[:lidx]), ","))
			out.UpText = up
			loadValues := strings.TrimSpace(rest[lidx+len("load average:"):])
			parts := strings.Split(loadValues, ",")
			if len(parts) >= 3 {
				out.LoadAvg[0] = parseFloat(parts[0])
				out.LoadAvg[1] = parseFloat(parts[1])
				out.LoadAvg[2] = parseFloat(parts[2])
			}
		}
	}
	return out
}

func parseProcLoadavg(s string) *ProcLoadAvg {
	line := firstNonEmptyLine(s)
	out := &ProcLoadAvg{Raw: line}
	fields := strings.Fields(line)
	if len(fields) >= 5 {
		out.Load[0] = parseFloat(fields[0])
		out.Load[1] = parseFloat(fields[1])
		out.Load[2] = parseFloat(fields[2])
		out.Procs = fields[3]
		out.Last = parseInt(fields[4])
	}
	return out
}

func parseIfconfig(s string) []Iface {
	var out []Iface
	for _, block := range splitIfconfigBlocks(s) {
		iface := parseIfconfigBlock(block)
		if iface.Name != "" {
			out = append(out, iface)
		}
	}
	return out
}

func splitIfconfigBlocks(s string) []string {
	lines := strings.Split(s, "\n")
	blocks := make([]string, 0, 8)
	current := make([]string, 0, 8)

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			if len(current) > 0 {
				blocks = append(blocks, strings.Join(current, "\n"))
				current = current[:0]
			}
			continue
		}
		current = append(current, line)
	}
	if len(current) > 0 {
		blocks = append(blocks, strings.Join(current, "\n"))
	}
	return blocks
}

func parseIfconfigBlock(block string) Iface {
	var out Iface
	lines := strings.Split(block, "\n")
	if len(lines) == 0 {
		return out
	}

	first := lines[0]
	firstFields := strings.Fields(first)
	if len(firstFields) > 0 {
		out.Name = firstFields[0]
	}
	if idx := strings.Index(first, "HWaddr"); idx >= 0 {
		rest := strings.TrimSpace(first[idx+len("HWaddr"):])
		fields := strings.Fields(rest)
		if len(fields) > 0 {
			out.HWAddr = fields[0]
		}
	}

	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "inet addr:") {
			out.IPv4 = between(line, "inet addr:", " ")
			out.Bcast = between(line, "Bcast:", " ")
			out.Netmask = between(line, "Mask:", " ")
		}
		if strings.HasPrefix(line, "inet6 addr:") && strings.Contains(line, "Scope:Link") {
			addr := strings.TrimSpace(strings.TrimPrefix(line, "inet6 addr:"))
			fields := strings.Fields(addr)
			if len(fields) > 0 {
				out.IPv6Link = fields[0]
			}
		}
		if strings.Contains(line, "MTU:") {
			out.MTU = afterInt(line, "MTU:")
		}
		if strings.HasPrefix(line, "RX packets:") {
			out.RxPackets = int64(afterInt(line, "RX packets:"))
			out.RxErrors = int64(afterInt(line, "errors:"))
			out.RxDropped = int64(afterInt(line, "dropped:"))
		}
		if strings.HasPrefix(line, "TX packets:") {
			out.TxPackets = int64(afterInt(line, "TX packets:"))
			out.TxErrors = int64(afterInt(line, "errors:"))
			out.TxDropped = int64(afterInt(line, "dropped:"))
		}
		if strings.HasPrefix(line, "RX bytes:") {
			out.RxBytes = parseInt64(firstFieldAfter(line, "RX bytes:"))
		}
		if strings.HasPrefix(line, "TX bytes:") {
			out.TxBytes = parseInt64(firstFieldAfter(line, "TX bytes:"))
		}
	}

	return out
}

func parseLanHosts(s string) []LanHost {
	var out []LanHost

	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Name") || strings.HasPrefix(line, "Command Successful") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		macIdx := -1
		for i, field := range fields {
			if looksLikeMAC(field) {
				macIdx = i
				break
			}
		}
		if macIdx < 0 {
			continue
		}

		host := LanHost{
			Name: fields[0],
			MAC:  fields[macIdx],
		}
		if macIdx+1 < len(fields) {
			host.AddressSource = fields[macIdx+1]
		}
		if macIdx+2 < len(fields) {
			host.Connection = fields[macIdx+2]
		}
		for _, token := range fields[1:macIdx] {
			if isIPv4(token) && host.IPv4 == "" {
				host.IPv4 = token
				continue
			}
			if (strings.Contains(token, ":") || strings.EqualFold(token, "N/A")) && host.IPv6 == "" {
				host.IPv6 = token
			}
		}
		out = append(out, host)
	}

	return out
}

func parsePortMap(s string) []PortMapEntry {
	var out []PortMapEntry
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if !isHexWithLen(fields[0], 12) || !isHex(fields[1]) {
			continue
		}
		out = append(out, PortMapEntry{
			MACNoColons: fields[0],
			PortCodeHex: fields[1],
		})
	}
	return out
}

func parseArp(s string) []ArpEntry {
	var out []ArpEntry
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		entry := ArpEntry{}
		if idx := strings.IndexByte(line, ' '); idx > 0 {
			entry.Host = line[:idx]
		}
		if l := strings.Index(line, "("); l >= 0 {
			if r := strings.Index(line[l:], ")"); r > 0 {
				entry.IPv4 = line[l+1 : l+r]
			}
		}
		if strings.Contains(line, "<incomplete>") {
			entry.State = "incomplete"
		} else {
			entry.State = "ok"
		}
		if idx := strings.Index(line, " at "); idx >= 0 {
			rest := line[idx+4:]
			fields := strings.Fields(rest)
			if len(fields) > 0 && looksLikeMAC(fields[0]) {
				entry.MAC = fields[0]
			}
		}
		if idx := strings.LastIndex(line, " on "); idx >= 0 {
			entry.Iface = strings.TrimSpace(line[idx+4:])
		}
		out = append(out, entry)
	}
	return out
}

func parseDnsmasqLeases(s string) []DhcpLease {
	var out []DhcpLease
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		out = append(out, DhcpLease{
			ExpirySeconds: parseInt64(fields[0]),
			MAC:           fields[1],
			IPv4:          fields[2],
			Hostname:      fields[3],
		})
	}
	return out
}

func parseEthctl(s string) []EthPort {
	var out []EthPort
	inStatus := false
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "status for eth ports") {
			inStatus = true
			continue
		}
		if !inStatus || strings.HasPrefix(line, "Interface") || strings.HasPrefix(line, "Command Successful") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		port := EthPort{
			Interface: fields[0],
			Raw:       line,
		}
		if len(fields) == 2 {
			port.Status = fields[1]
		} else {
			port.Duplex = fields[1]
			port.Speed = parseInt(fields[2])
			if len(fields) >= 4 {
				value := parseInt(fields[3])
				port.Enable = &value
			}
		}
		out = append(out, port)
	}
	return out
}

func parseWifiAssoc(s string) []WifiAssoc {
	var out []WifiAssoc
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Address") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		row := WifiAssoc{Address: fields[0]}
		if len(fields) >= 2 {
			row.RateKbps = parseInt(fields[1])
		}
		if len(fields) >= 3 {
			row.RSSI = parseInt(fields[2])
		}
		if len(fields) >= 4 {
			row.SNR = parseInt(fields[3])
		}
		if len(fields) >= 5 {
			row.Level = parseInt(fields[4])
		}
		out = append(out, row)
	}
	return out
}

func parseWlanCfg(s string, includePSK bool) []WlanRow {
	var out []WlanRow
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Index") || strings.HasPrefix(line, "Command Successful") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		row := WlanRow{
			Raw:          line,
			Index:        parseInt(fields[0]),
			Band:         fields[1],
			SSID:         fields[2],
			Enable:       parseInt(fields[3]),
			Bandwidth:    fields[4],
			Channel:      fields[5],
			MaxDevices:   parseInt(fields[6]),
			SecurityMode: fields[7],
		}

		if includePSK {
			row.PskValue = fields[8]
		} else {
			row.PskValue = redact(fields[8])
		}
		if len(fields) >= 10 {
			row.PMF = fields[9]
		}

		out = append(out, row)
	}
	return out
}

func parseSfp(s string) *SfpInfo {
	out := &SfpInfo{Raw: s}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(line, "sfp/bosa present") && strings.Contains(line, "=") {
			value := strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
			switch value {
			case "1":
				b := true
				out.Present = &b
			case "0":
				b := false
				out.Present = &b
			}
		}

		if strings.HasPrefix(line, "DDMI vendor name") {
			out.VendorName = afterEq(line)
		}
		if strings.HasPrefix(line, "DDMI part number") {
			out.PartNumber = afterEq(line)
		}
		if strings.HasPrefix(line, "DDMI serial number") {
			out.SerialNumber = afterEq(line)
		}
		if strings.HasPrefix(line, "DDMI rx power") {
			value := parseFloat(afterEq(line))
			out.RxPowerDbm = &value
		}
		if strings.HasPrefix(line, "DDMI tx power") {
			value := parseFloat(afterEq(line))
			out.TxPowerDbm = &value
		}
		if strings.HasPrefix(line, "DDMI temperature") {
			value := parseFloat(afterEq(line))
			out.TemperatureC = &value
		}
		if strings.HasPrefix(line, "sfp link state") {
			out.LinkState = afterEq(line)
		}
		if strings.HasPrefix(line, "sfp duplex mode") {
			out.Duplex = afterEq(line)
		}
		if strings.HasPrefix(line, "sfp speed") {
			speedFields := strings.Fields(afterEq(line))
			if len(speedFields) > 0 {
				value := parseInt(speedFields[0])
				out.SpeedMbit = &value
			}
		}
	}
	return out
}

func parseUbusSystemInfo(s string) (map[string]string, *UptimeInfo) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(s), &payload); err != nil {
		return nil, nil
	}

	out := make(map[string]string, 8)
	copyJSONField(out, payload, "Hostname", "hostname")
	copyJSONField(out, payload, "Model", "model")
	copyJSONField(out, payload, "Kernel", "kernel")
	copyJSONField(out, payload, "System", "system")
	copyJSONField(out, payload, "BoardName", "board_name")

	if release, ok := payload["release"].(map[string]any); ok {
		copyJSONField(out, release, "ReleaseDistribution", "distribution")
		copyJSONField(out, release, "ReleaseVersion", "version")
		copyJSONField(out, release, "ReleaseRevision", "revision")
		copyJSONField(out, release, "ReleaseDescription", "description")
	}
	if len(out) == 0 {
		out = nil
	}

	uptimeSeconds, ok := toFloat64(payload["uptime"])
	if !ok {
		return out, nil
	}
	uptime := &UptimeInfo{
		Raw:    fmt.Sprintf("%.0f", uptimeSeconds),
		UpText: fmt.Sprintf("%.0fs", uptimeSeconds),
	}
	return out, uptime
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func parseInt(s string) int {
	v, _ := strconv.Atoi(strings.TrimSpace(s))
	return v
}

func parseInt64(s string) int64 {
	v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return v
}

func parseFloat(s string) float64 {
	value := strings.TrimSpace(strings.ToLower(s))
	value = strings.TrimSuffix(value, "dbm")
	value = strings.TrimSuffix(value, "c")
	value = strings.TrimSpace(value)
	v, _ := strconv.ParseFloat(value, 64)
	return v
}

func afterEq(line string) string {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func between(s, left, endDelim string) string {
	idx := strings.Index(s, left)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimLeft(s[idx+len(left):], " ")
	if endDelim == "" {
		return strings.TrimSpace(rest)
	}
	parts := strings.SplitN(rest, endDelim, 2)
	return strings.TrimSpace(parts[0])
}

func firstFieldAfter(line, key string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(line[idx+len(key):]))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func copyJSONField(dst map[string]string, src map[string]any, dstKey, srcKey string) {
	v, ok := src[srcKey]
	if !ok {
		return
	}
	switch t := v.(type) {
	case string:
		t = strings.TrimSpace(t)
		if t != "" {
			dst[dstKey] = t
		}
	case float64:
		dst[dstKey] = fmt.Sprintf("%v", t)
	case bool:
		if t {
			dst[dstKey] = "true"
		} else {
			dst[dstKey] = "false"
		}
	}
}

func toFloat64(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	default:
		return 0, false
	}
}

func afterInt(line, key string) int {
	idx := strings.Index(line, key)
	if idx < 0 {
		return 0
	}
	rest := strings.TrimLeft(line[idx+len(key):], " ")
	var b strings.Builder
	for _, r := range rest {
		if r < '0' || r > '9' {
			break
		}
		b.WriteRune(r)
	}
	return parseInt(b.String())
}

func looksLikeMAC(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 17 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (i+1)%3 == 0 {
			if s[i] != ':' {
				return false
			}
			continue
		}
		if !((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')) {
			return false
		}
	}
	return true
}

func isIPv4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.To4() != nil
}

func redact(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" || s == "-" {
		return s
	}
	if len(s) <= 2 {
		return "**"
	}
	return strings.Repeat("*", len(s)-2) + s[len(s)-2:]
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		isDigit := r >= '0' && r <= '9'
		isLower := r >= 'a' && r <= 'f'
		isUpper := r >= 'A' && r <= 'F'
		if !(isDigit || isLower || isUpper) {
			return false
		}
	}
	return true
}

func isHexWithLen(s string, n int) bool {
	return len(s) == n && isHex(s)
}
