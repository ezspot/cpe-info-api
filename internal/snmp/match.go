package snmp

import "strings"

// resolvePort finds the ifIndex whose interface name best matches a user-supplied
// label. Users pass CLI shorthand ("6/2", "Gi6/2") but SNMP returns the long form
// ("GigabitEthernet6/2"), so matching is layered: exact, canonical type+tuple, then
// bare slot/port tuple. A bare-tuple match is only accepted when unambiguous.
func resolvePort(rows map[int]*ifRow, label string) (int, bool) {
	label = strings.TrimSpace(label)
	if label == "" {
		return 0, false
	}

	for idx, r := range rows {
		if strings.EqualFold(r.name, label) || strings.EqualFold(r.descr, label) {
			return idx, true
		}
	}

	want := canonicalName(label)
	for idx, r := range rows {
		if canonicalName(r.name) == want || canonicalName(r.descr) == want {
			return idx, true
		}
	}

	wantTuple := portTuple(label)
	if wantTuple == "" {
		return 0, false
	}
	candidates := tupleCandidates(wantTuple)
	matches := make([]int, 0, 2)
	for idx, r := range rows {
		if candidates[portTuple(r.name)] || candidates[portTuple(r.descr)] {
			matches = append(matches, idx)
		}
	}
	if len(matches) == 1 {
		return matches[0], true
	}
	return 0, false
}

// tupleCandidates returns the slot/port tuples that should be considered
// equivalent, bridging 2-tuple CLI shorthand and 3-tuple stacked names
// (e.g. "3/20" <-> "3/0/20").
func tupleCandidates(tuple string) map[string]bool {
	out := map[string]bool{tuple: true}
	parts := strings.Split(tuple, "/")
	switch {
	case len(parts) == 2:
		out[parts[0]+"/0/"+parts[1]] = true
	case len(parts) == 3 && parts[1] == "0":
		out[parts[0]+"/"+parts[2]] = true
	}
	return out
}

// canonicalName reduces an interface label to "<typeToken>:<tuple>", e.g.
// "GigabitEthernet6/2" and "Gi6/2" both become "ge:6/2".
func canonicalName(s string) string {
	prefix, rest := splitLabel(s)
	return typeToken(prefix) + ":" + portTuple(rest)
}

func portTuple(s string) string {
	_, rest := splitLabel(s)
	var b strings.Builder
	for _, r := range rest {
		switch {
		case r >= '0' && r <= '9', r == '/', r == '.':
			b.WriteRune(r)
		case r == ' ':
			return b.String()
		}
	}
	return b.String()
}

// splitLabel separates the interface-type prefix from the slot/port remainder.
// It also absorbs a leading speed number into the prefix so digit-first Huawei
// short forms parse correctly (e.g. "100GE1/0/5" -> prefix "100ge", rest "1/0/5").
func splitLabel(s string) (prefix, rest string) {
	s = strings.ToLower(strings.TrimSpace(s))
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 || i >= len(s) || !isLetter(s[i]) {
		i = 0 // no speed prefix; a pure-numeric lead is the tuple
	}
	for i < len(s) && isLetter(s[i]) {
		i++
	}
	return strings.TrimSpace(s[:i]), s[i:]
}

func isLetter(b byte) bool {
	return b >= 'a' && b <= 'z'
}

func typeToken(prefix string) string {
	switch prefix {
	case "gigabitethernet", "gi", "ge":
		return "ge"
	case "tengigabitethernet", "te", "xge", "xgigabitethernet":
		return "10g"
	case "twentyfivegige", "twentyfivegigabitethernet", "25ge":
		return "25g"
	case "fortygigabitethernet", "fo", "40ge":
		return "40g"
	case "hundredgige", "hu", "100ge":
		return "100g"
	case "fastethernet", "fa":
		return "fa"
	case "ethernet", "eth", "e":
		return "eth"
	default:
		return prefix
	}
}
