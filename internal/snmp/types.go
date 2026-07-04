package snmp

import "time"

type PortQuery struct {
	Host             string
	Port             string
	ReverseDirection bool
	IncludeMACs      bool
}

type PortResponse struct {
	Host       string       `json:"host"`
	SNMPPort   int          `json:"snmpPort"`
	Switch     string       `json:"switch,omitempty"`
	PollTime   time.Time    `json:"pollTime"`
	SNMPFailed bool         `json:"snmpFailed"`
	Retryable  bool         `json:"retryable,omitempty"`
	Errors     []string     `json:"errors,omitempty"`
	Ports      []PortStatus `json:"ports,omitempty"`
} // @Name SwitchPortResponse

type PortStatus struct {
	Switch         string     `json:"switch,omitempty"`
	IfIndex        int        `json:"ifIndex"`
	Port           string     `json:"port"`
	Description    string     `json:"description,omitempty"`
	AdminStatus    string     `json:"adminStatus"`
	OperStatus     string     `json:"operStatus"`
	StatusDuration string     `json:"statusDuration,omitempty"`
	StatusSeconds  *int64     `json:"statusSeconds,omitempty"`
	SpeedMbps      uint64     `json:"speedMbps"`
	Duplex         string     `json:"duplex,omitempty"`
	DsPacketErrors uint64     `json:"dsPacketErrors"`
	UsPacketErrors uint64     `json:"usPacketErrors"`
	DsBytes        uint64     `json:"dsBytes"`
	UsBytes        uint64     `json:"usBytes"`
	DsDataMB       float64    `json:"dsDataMB"`
	UsDataMB       float64    `json:"usDataMB"`
	Optics         *Optics    `json:"optics,omitempty"`
	MACs           []MACEntry `json:"macs,omitempty"`
	PollTime       time.Time  `json:"pollTime"`
} // @Name SwitchPortStatus

type MACEntry struct {
	MAC  string `json:"mac"`
	VLAN int    `json:"vlan,omitempty"`
} // @Name SwitchPortMAC

type Optics struct {
	RxPowerDbm   *float64 `json:"rxPowerDbm,omitempty"`
	TxPowerDbm   *float64 `json:"txPowerDbm,omitempty"`
	TemperatureC *float64 `json:"temperatureC,omitempty"`
	VoltageV     *float64 `json:"voltageV,omitempty"`
	CurrentMA    *float64 `json:"currentMa,omitempty"`
} // @Name SwitchPortOptics

// ifRow is the raw per-interface data assembled from SNMP column walks,
// keyed by ifIndex, before direction mapping and formatting.
type ifRow struct {
	ifIndex     int
	name        string
	descr       string
	alias       string
	adminStatus int
	operStatus  int
	lastChange  uint32
	highSpeed   uint64
	hcIn        uint64
	hcOut       uint64
	inErrors    uint64
	outErrors   uint64
	duplex      int
	hasDuplex   bool
	optics      *Optics
	macs        []MACEntry
}
