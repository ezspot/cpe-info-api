package cpe

import "time"

type ActionOptions struct {
	Model   string            `json:"model,omitempty"`
	Action  string            `json:"action"`
	Params  map[string]string `json:"params,omitempty"`
	DryRun  bool              `json:"dryRun,omitempty"`
	Profile string            `json:"profile,omitempty"`
}

type CollectOptions struct {
	IncludeRaw bool
	IncludePSK bool
	Model      string
}

type ActionResponse struct {
	IP          string            `json:"ip"`
	Port        int               `json:"port"`
	Model       string            `json:"model,omitempty"`
	Action      string            `json:"action"`
	Profile     string            `json:"profile,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	DryRun      bool              `json:"dryRun,omitempty"`
	SSHFailed   bool              `json:"sshFailed"`
	Success     bool              `json:"success"`
	Errors      []string          `json:"errors,omitempty"`
	Command     string            `json:"command,omitempty"`
	Params      map[string]string `json:"params,omitempty"`
	Output      string            `json:"output,omitempty"`
	Warnings    []string          `json:"warnings,omitempty"`
	RequestID   string            `json:"requestId,omitempty"`
	Retryable   bool              `json:"retryable,omitempty"`
	CompletedAt *time.Time        `json:"completedAt,omitempty"`
}

type CollectResponse struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Model     string    `json:"model,omitempty"`
	Timestamp time.Time `json:"timestamp"`

	SSHFailed bool     `json:"sshFailed"`
	Errors    []string `json:"errors,omitempty"`

	CpeInfo  map[string]string `json:"cpeInfo,omitempty"`
	Uptime   *UptimeInfo       `json:"uptime,omitempty"`
	LoadAvg  *ProcLoadAvg      `json:"loadAvg,omitempty"`
	Ifaces   []Iface           `json:"interfaces,omitempty"`
	LanHosts []LanHost         `json:"lanHosts,omitempty"`
	PortMap  []PortMapEntry    `json:"portMap,omitempty"`
	ARP      []ArpEntry        `json:"arp,omitempty"`
	Leases   []DhcpLease       `json:"dhcpLeases,omitempty"`
	EthPorts []EthPort         `json:"ethPorts,omitempty"`
	Wifi2    []WifiAssoc       `json:"wifi24Assoc,omitempty"`
	Wifi5    []WifiAssoc       `json:"wifi50Assoc,omitempty"`
	WlanCfg  []WlanRow         `json:"wlanConfig,omitempty"`
	Sfp      *SfpInfo          `json:"sfp,omitempty"`

	Raw map[string]string `json:"raw,omitempty"`
}

type UptimeInfo struct {
	Raw       string     `json:"raw"`
	UpText    string     `json:"upText,omitempty"`
	LoadAvg   [3]float64 `json:"loadAvg,omitempty"`
	ClockTime string     `json:"clockTime,omitempty"`
}

type ProcLoadAvg struct {
	Raw   string     `json:"raw"`
	Load  [3]float64 `json:"load,omitempty"`
	Procs string     `json:"procs,omitempty"`
	Last  int        `json:"lastPid,omitempty"`
}

type Iface struct {
	Name      string `json:"name"`
	HWAddr    string `json:"hwaddr,omitempty"`
	IPv4      string `json:"ipv4,omitempty"`
	Netmask   string `json:"netmask,omitempty"`
	Bcast     string `json:"broadcast,omitempty"`
	IPv6Link  string `json:"ipv6LinkLocal,omitempty"`
	MTU       int    `json:"mtu,omitempty"`
	RxPackets int64  `json:"rxPackets,omitempty"`
	TxPackets int64  `json:"txPackets,omitempty"`
	RxBytes   int64  `json:"rxBytes,omitempty"`
	TxBytes   int64  `json:"txBytes,omitempty"`
	RxErrors  int64  `json:"rxErrors,omitempty"`
	TxErrors  int64  `json:"txErrors,omitempty"`
	RxDropped int64  `json:"rxDropped,omitempty"`
	TxDropped int64  `json:"txDropped,omitempty"`
}

type LanHost struct {
	Name          string `json:"name,omitempty"`
	IPv4          string `json:"ipv4,omitempty"`
	IPv6          string `json:"ipv6,omitempty"`
	MAC           string `json:"mac,omitempty"`
	AddressSource string `json:"addressSource,omitempty"`
	Connection    string `json:"connectionType,omitempty"`
}

type PortMapEntry struct {
	MACNoColons string `json:"macNoColons"`
	PortCodeHex string `json:"portCodeHex"`
}

type ArpEntry struct {
	Host  string `json:"host,omitempty"`
	IPv4  string `json:"ipv4,omitempty"`
	MAC   string `json:"mac,omitempty"`
	Iface string `json:"iface,omitempty"`
	State string `json:"state,omitempty"`
}

type DhcpLease struct {
	ExpirySeconds int64  `json:"expirySeconds,omitempty"`
	MAC           string `json:"mac,omitempty"`
	IPv4          string `json:"ipv4,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
}

type EthPort struct {
	Interface string `json:"interface"`
	Duplex    string `json:"duplex,omitempty"`
	Speed     int    `json:"speed,omitempty"`
	Enable    *int   `json:"enable,omitempty"`
	Status    string `json:"status,omitempty"`
	Raw       string `json:"raw,omitempty"`
}

type WifiAssoc struct {
	Address  string `json:"address"`
	RateKbps int    `json:"rateKbps,omitempty"`
	RSSI     int    `json:"rssi,omitempty"`
	SNR      int    `json:"snr,omitempty"`
	Level    int    `json:"level,omitempty"`
}

type WlanRow struct {
	Index        int    `json:"index"`
	Band         string `json:"band,omitempty"`
	SSID         string `json:"ssid,omitempty"`
	Enable       int    `json:"enable,omitempty"`
	Bandwidth    string `json:"bandwidth,omitempty"`
	Channel      string `json:"channel,omitempty"`
	MaxDevices   int    `json:"maxDevices,omitempty"`
	SecurityMode string `json:"securityMode,omitempty"`
	PskValue     string `json:"pskValue,omitempty"`
	PMF          string `json:"pmf,omitempty"`
	Raw          string `json:"raw,omitempty"`
}

type SfpInfo struct {
	Raw          string   `json:"raw"`
	Present      *bool    `json:"present,omitempty"`
	VendorName   string   `json:"vendorName,omitempty"`
	PartNumber   string   `json:"partNumber,omitempty"`
	SerialNumber string   `json:"serialNumber,omitempty"`
	RxPowerDbm   *float64 `json:"rxPowerDbm,omitempty"`
	TxPowerDbm   *float64 `json:"txPowerDbm,omitempty"`
	TemperatureC *float64 `json:"temperatureC,omitempty"`
	LinkState    string   `json:"linkState,omitempty"`
	Duplex       string   `json:"duplex,omitempty"`
	SpeedMbit    *int     `json:"speedMbit,omitempty"`
}
