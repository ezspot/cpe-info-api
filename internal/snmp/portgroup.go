package snmp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// PortGroup is a parsed RADIUS port-group identifier such as
// "TAFAALLERSTADAR3S003P20": prefix TAF (Cisco) / NVF (Huawei), a switch key
// (region+location+ARn), card Sxxx, and port Pyy.
type PortGroup struct {
	Raw       string
	Vendor    string
	SwitchKey string
	Card      int
	Port      int
	Interface string
}

var portGroupPattern = regexp.MustCompile(`^(TAF|NVF)(.*AR\d+)S0*(\d+)P0*(\d+)$`)

func ParsePortGroup(s string) (PortGroup, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	m := portGroupPattern.FindStringSubmatch(s)
	if m == nil {
		return PortGroup{}, fmt.Errorf("invalid port group %q", s)
	}
	card, err := strconv.Atoi(m[3])
	if err != nil {
		return PortGroup{}, fmt.Errorf("invalid card in port group %q", s)
	}
	port, err := strconv.Atoi(m[4])
	if err != nil {
		return PortGroup{}, fmt.Errorf("invalid port in port group %q", s)
	}
	vendor := "cisco"
	if m[1] == "NVF" {
		vendor = "huawei"
	}
	return PortGroup{
		Raw:       s,
		Vendor:    vendor,
		SwitchKey: normalizeHostKey(m[1] + m[2]),
		Card:      card,
		Port:      port,
		Interface: fmt.Sprintf("%d/%d", card, port),
	}, nil
}

// HostResolver maps a normalized switch key to a management IP, loaded from a
// hosts file (lines of "IP hostname", '#' comments ignored).
type HostResolver struct {
	byKey map[string]string
}

func NewHostResolver(path string) (*HostResolver, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open switch hosts file: %w", err)
	}
	defer f.Close()

	byKey := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if net.ParseIP(fields[0]) == nil {
			continue
		}
		key := normalizeHostKey(fields[1])
		if existing, ok := byKey[key]; ok && existing != fields[0] {
			return nil, fmt.Errorf("switch hosts file: %q and another host normalize to %q but map to different IPs (%s, %s)", fields[1], key, existing, fields[0])
		}
		byKey[key] = fields[0]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read switch hosts file: %w", err)
	}
	return &HostResolver{byKey: byKey}, nil
}

func (r *HostResolver) Resolve(switchKey string) (string, bool) {
	ip, ok := r.byKey[switchKey]
	return ip, ok
}

func normalizeHostKey(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i] // first label of an FQDN
	}
	return strings.ReplaceAll(h, "-", "")
}
