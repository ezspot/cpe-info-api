package snmp

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

func invalidV3(key, value string) error {
	return fmt.Errorf("invalid %s %q", key, value)
}

func buildPortStatuses(rows map[int]*ifRow, sysName string, sysUpTime uint32, pollTime time.Time, reverse bool) []PortStatus {
	out := make([]PortStatus, 0, len(rows))
	for _, r := range rows {
		out = append(out, buildPortStatus(r, sysName, sysUpTime, pollTime, reverse))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IfIndex < out[j].IfIndex })
	return out
}

func buildPortStatus(r *ifRow, sysName string, sysUpTime uint32, pollTime time.Time, reverse bool) PortStatus {
	status := PortStatus{
		Switch:      sysName,
		IfIndex:     r.ifIndex,
		Port:        portLabel(r),
		Description: r.alias,
		AdminStatus: adminStatusName(r.adminStatus),
		OperStatus:  operStatusName(r.operStatus),
		SpeedMbps:   r.highSpeed,
		PollTime:    pollTime,
	}
	if r.hasDuplex {
		status.Duplex = duplexName(r.duplex)
	}
	status.Optics = r.optics
	status.MACs = r.macs

	if secs, ok := statusDurationSeconds(sysUpTime, r.lastChange); ok {
		status.StatusSeconds = &secs
		status.StatusDuration = formatDuration(secs)
	}

	// Ds (downstream) = toward subscriber = switch egress (Out); Us = ingress (In).
	dsBytes, usBytes := r.hcOut, r.hcIn
	dsErrors, usErrors := r.outErrors, r.inErrors
	if reverse {
		dsBytes, usBytes = usBytes, dsBytes
		dsErrors, usErrors = usErrors, dsErrors
	}
	status.DsBytes = dsBytes
	status.UsBytes = usBytes
	status.DsPacketErrors = dsErrors
	status.UsPacketErrors = usErrors
	status.DsDataMB = bytesToMB(dsBytes)
	status.UsDataMB = bytesToMB(usBytes)

	return status
}

func portLabel(r *ifRow) string {
	if r.name != "" {
		return r.name
	}
	return r.descr
}

func bytesToMB(b uint64) float64 {
	return float64(b) / 1_000_000
}

// statusDurationSeconds returns time-in-current-operational-state. ifLastChange
// is a snapshot of sysUpTime; 0 means the transition predates the last agent
// re-init, and sysUpTime < ifLastChange implies a wrap/restart. Both are unknown.
func statusDurationSeconds(sysUpTime, lastChange uint32) (int64, bool) {
	if lastChange == 0 || sysUpTime < lastChange {
		return 0, false
	}
	return int64(sysUpTime-lastChange) / 100, true
}

func formatDuration(seconds int64) string {
	if seconds < 0 {
		seconds = 0
	}
	d := seconds / 86400
	h := (seconds % 86400) / 3600
	m := (seconds % 3600) / 60
	s := seconds % 60
	return fmt.Sprintf("%dd %dh %dm %ds", d, h, m, s)
}

func adminStatusName(v int) string {
	switch v {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	default:
		return "unknown"
	}
}

func operStatusName(v int) string {
	switch v {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	case 4:
		return "unknown"
	case 5:
		return "dormant"
	case 6:
		return "notPresent"
	case 7:
		return "lowerLayerDown"
	default:
		return "unknown"
	}
}

func duplexName(v int) string {
	switch v {
	case 2:
		return "half"
	case 3:
		return "full"
	default:
		return "unknown"
	}
}

func classifySNMPError(err error) (reason, hint string) {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "timed out"), strings.Contains(msg, "deadline exceeded"):
		return "timeout", "no SNMP response; verify the agent is enabled, the community/credentials, and UDP/161 reachability"
	case strings.Contains(msg, "no route to host"), strings.Contains(msg, "unreachable"):
		return "unreachable", "target unreachable; verify the management IP and network path"
	case strings.Contains(msg, "refused"):
		return "connection_refused", "port refused; verify the SNMP port and any ACL"
	case strings.Contains(msg, "authentication"), strings.Contains(msg, "wrong digest"), strings.Contains(msg, "decryption"), strings.Contains(msg, "usm"):
		return "auth_failed", "SNMPv3 authentication failed; verify user, auth/priv protocols and passphrases"
	default:
		return "other", ""
	}
}
