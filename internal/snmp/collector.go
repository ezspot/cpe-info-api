package snmp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"device-api/internal/config"
	"device-api/internal/observability"

	"github.com/gosnmp/gosnmp"
)

type Collector struct {
	cfg     config.SNMPConfig
	log     *slog.Logger
	metrics *observability.Registry
}

func NewCollector(cfg config.SNMPConfig, logger *slog.Logger, metrics *observability.Registry) *Collector {
	if metrics == nil {
		metrics = observability.NewRegistry()
	}
	return &Collector{cfg: cfg, log: logger, metrics: metrics}
}

func (c *Collector) IsAllowedTarget(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range c.cfg.AllowedTargetCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *Collector) CollectPorts(ctx context.Context, q PortQuery) PortResponse {
	start := time.Now()
	response := PortResponse{
		Host:     q.Host,
		SNMPPort: c.cfg.Port,
		PollTime: time.Now().UTC(),
	}

	if !c.cfg.Configured() {
		response.SNMPFailed = true
		response.Errors = append(response.Errors, "snmp polling is not configured on this server")
		c.metrics.ObserveSNMPRequest("snmp_failed", time.Since(start))
		return response
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()

	client, err := c.dial(ctx, q.Host)
	if err != nil {
		return c.fail(response, "snmp connect", err, start)
	}
	defer client.Close()

	sysName, sysUpTime, err := c.readSystem(client)
	if err != nil {
		return c.fail(response, "snmp read system", err, start)
	}
	response.Switch = sysName

	rows, err := c.readInterfaces(client)
	if err != nil {
		return c.fail(response, "snmp walk interfaces", err, start)
	}

	selected := rows
	if q.Port != "" {
		idx, ok := resolvePort(rows, q.Port)
		if !ok {
			response.Errors = append(response.Errors, fmt.Sprintf("port %q not found on device", q.Port))
			c.metrics.ObserveSNMPRequest("not_found", time.Since(start))
			return response
		}
		selected = map[int]*ifRow{idx: rows[idx]}
	}

	c.enrichOptics(client, selected)
	if q.IncludeMACs {
		c.enrichMACs(client, selected)
	}

	response.Ports = buildPortStatuses(selected, sysName, sysUpTime, response.PollTime, q.ReverseDirection)
	c.metrics.ObserveSNMPRequest("success", time.Since(start))
	c.log.Info("snmp_collect_done",
		"host", q.Host,
		"switch", sysName,
		"ports", len(response.Ports),
		"duration_ms", time.Since(start).Milliseconds(),
	)
	return response
}

func (c *Collector) fail(response PortResponse, stage string, err error, start time.Time) PortResponse {
	reason, hint := classifySNMPError(err)
	message := stage + ": " + err.Error()
	if hint != "" {
		message += " (" + hint + ")"
	}
	response.SNMPFailed = true
	response.Retryable = reason == "timeout" || reason == "unreachable"
	response.Errors = append(response.Errors, message)
	c.metrics.ObserveSNMPFailure(reason)
	c.metrics.ObserveSNMPRequest("snmp_failed", time.Since(start))
	c.log.Error("snmp_failed", "host", response.Host, "stage", stage, "reason", reason, "error", err.Error())
	return response
}

func (c *Collector) dial(ctx context.Context, host string) (*gosnmp.GoSNMP, error) {
	client := &gosnmp.GoSNMP{
		Target:             host,
		Port:               uint16(c.cfg.Port),
		Transport:          "udp",
		Timeout:            c.cfg.Timeout,
		Retries:            c.cfg.Retries,
		ExponentialTimeout: false,
		MaxOids:            gosnmp.MaxOids,
		MaxRepetitions:     c.cfg.MaxRepetitions,
		Context:            ctx,
	}

	if c.cfg.Version == "3" {
		client.Version = gosnmp.Version3
		client.SecurityModel = gosnmp.UserSecurityModel
		flags, err := v3MsgFlags(c.cfg.V3Level)
		if err != nil {
			return nil, err
		}
		client.MsgFlags = flags
		authProto, err := v3AuthProtocol(c.cfg.V3AuthProtocol)
		if err != nil {
			return nil, err
		}
		privProto, err := v3PrivProtocol(c.cfg.V3PrivProtocol)
		if err != nil {
			return nil, err
		}
		client.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 c.cfg.V3User,
			AuthenticationProtocol:   authProto,
			AuthenticationPassphrase: c.cfg.V3AuthPassphrase,
			PrivacyProtocol:          privProto,
			PrivacyPassphrase:        c.cfg.V3PrivPassphrase,
		}
	} else {
		client.Version = gosnmp.Version2c
		client.Community = c.cfg.Community
	}

	if err := client.Connect(); err != nil {
		return nil, err
	}
	return client, nil
}

func (c *Collector) readSystem(client *gosnmp.GoSNMP) (sysName string, sysUpTime uint32, err error) {
	packet, err := client.Get([]string{oidSysName, oidSysUpTime})
	if err != nil {
		return "", 0, err
	}
	for i := range packet.Variables {
		v := packet.Variables[i]
		switch {
		case strings.HasPrefix(strings.TrimPrefix(v.Name, "."), strings.TrimPrefix(oidSysName, ".")):
			sysName = pduString(v)
		case strings.HasPrefix(strings.TrimPrefix(v.Name, "."), strings.TrimPrefix(oidSysUpTime, ".")):
			sysUpTime = uint32(pduUint(v))
		}
	}
	return sysName, sysUpTime, nil
}

func (c *Collector) readInterfaces(client *gosnmp.GoSNMP) (map[int]*ifRow, error) {
	rows := make(map[int]*ifRow)
	row := func(idx int) *ifRow {
		r, ok := rows[idx]
		if !ok {
			r = &ifRow{ifIndex: idx}
			rows[idx] = r
		}
		return r
	}

	columns := []struct {
		oid   string
		apply func(r *ifRow, pdu gosnmp.SnmpPDU)
	}{
		{colIfName, func(r *ifRow, p gosnmp.SnmpPDU) { r.name = pduString(p) }},
		{colIfDescr, func(r *ifRow, p gosnmp.SnmpPDU) { r.descr = pduString(p) }},
		{colIfAlias, func(r *ifRow, p gosnmp.SnmpPDU) { r.alias = pduString(p) }},
		{colIfAdminStatus, func(r *ifRow, p gosnmp.SnmpPDU) { r.adminStatus = int(pduUint(p)) }},
		{colIfOperStatus, func(r *ifRow, p gosnmp.SnmpPDU) { r.operStatus = int(pduUint(p)) }},
		{colIfLastChange, func(r *ifRow, p gosnmp.SnmpPDU) { r.lastChange = uint32(pduUint(p)) }},
		{colIfHighSpeed, func(r *ifRow, p gosnmp.SnmpPDU) { r.highSpeed = pduUint(p) }},
		{colIfHCInOctets, func(r *ifRow, p gosnmp.SnmpPDU) { r.hcIn = pduUint(p) }},
		{colIfHCOutOctets, func(r *ifRow, p gosnmp.SnmpPDU) { r.hcOut = pduUint(p) }},
		{colIfInErrors, func(r *ifRow, p gosnmp.SnmpPDU) { r.inErrors = pduUint(p) }},
		{colIfOutErrors, func(r *ifRow, p gosnmp.SnmpPDU) { r.outErrors = pduUint(p) }},
		{colDot3Duplex, func(r *ifRow, p gosnmp.SnmpPDU) { r.duplex = int(pduUint(p)); r.hasDuplex = true }},
	}

	for _, col := range columns {
		pdus, err := client.BulkWalkAll(col.oid)
		if err != nil {
			// ifName may be empty on some agents; ifDescr is the required baseline.
			if col.oid == colIfName {
				continue
			}
			return nil, fmt.Errorf("walk %s: %w", col.oid, err)
		}
		for i := range pdus {
			pdu := pdus[i]
			if isException(pdu) {
				continue
			}
			idx, ok := trailingIndex(pdu.Name)
			if !ok {
				continue
			}
			col.apply(row(idx), pdu)
		}
	}

	return rows, nil
}

func trailingIndex(name string) (int, bool) {
	name = strings.TrimRight(name, ".")
	pos := strings.LastIndex(name, ".")
	if pos < 0 {
		return 0, false
	}
	idx, err := strconv.Atoi(name[pos+1:])
	if err != nil {
		return 0, false
	}
	return idx, true
}
