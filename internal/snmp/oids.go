package snmp

// Scalar OIDs (instance .0).
const (
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
)

// ENTITY-MIB (RFC 6933). entAliasMappingIdentifier value is an OID ending in ifIndex.
const (
	colEntPhysicalDescr       = "1.3.6.1.2.1.47.1.1.1.1.2"
	colEntPhysicalContainedIn = "1.3.6.1.2.1.47.1.1.1.1.4"
	colEntPhysicalClass       = "1.3.6.1.2.1.47.1.1.1.1.5"
	colEntPhysicalName        = "1.3.6.1.2.1.47.1.1.1.1.7"
	colEntAliasMapping        = "1.3.6.1.2.1.47.1.3.2.1.2"
)

const (
	entClassModule = 9
	entClassPort   = 10
)

// CISCO-ENTITY-SENSOR-MIB (1.3.6.1.4.1.9.9.91), indexed by entPhysicalIndex.
const (
	colCiscoSensorType      = "1.3.6.1.4.1.9.9.91.1.1.1.1.1"
	colCiscoSensorScale     = "1.3.6.1.4.1.9.9.91.1.1.1.1.2"
	colCiscoSensorPrecision = "1.3.6.1.4.1.9.9.91.1.1.1.1.3"
	colCiscoSensorValue     = "1.3.6.1.4.1.9.9.91.1.1.1.1.4"
	colCiscoSensorStatus    = "1.3.6.1.4.1.9.9.91.1.1.1.1.5"
)

const (
	ciscoSensorVoltsDC  = 4
	ciscoSensorAmperes  = 5
	ciscoSensorWatts    = 6
	ciscoSensorCelsius  = 8
	ciscoSensorDBm      = 14
	ciscoSensorStatusOK = 1

	ciscoPrecisionSentinel = 1615384784
)

// HUAWEI-ENTITY-EXTENT-MIB hwOpticalModuleInfoTable, indexed by entPhysicalIndex.
const (
	colHuaweiOpticalTemperature = "1.3.6.1.4.1.2011.5.25.31.1.1.3.1.5"
	colHuaweiOpticalVoltage     = "1.3.6.1.4.1.2011.5.25.31.1.1.3.1.6"
	colHuaweiOpticalBiasCurrent = "1.3.6.1.4.1.2011.5.25.31.1.1.3.1.7"
	colHuaweiOpticalRxPower     = "1.3.6.1.4.1.2011.5.25.31.1.1.3.1.8"
	colHuaweiOpticalTxPower     = "1.3.6.1.4.1.2011.5.25.31.1.1.3.1.9"
)

const huaweiOpticalSentinel = 2147483647

// BRIDGE-MIB / Q-BRIDGE-MIB forwarding database (learned MACs per bridge port).
const (
	colDot1dBasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2"
	colDot1qTpFdbPort       = "1.3.6.1.2.1.17.7.1.2.2.1.2"
	colDot1qTpFdbStatus     = "1.3.6.1.2.1.17.7.1.2.2.1.3"
)

const fdbStatusLearned = 3

// maxMACsPerPort bounds the learned MACs attached to a single interface so an
// all-ports query against a large FDB (e.g. a trunk/uplink) cannot balloon.
const maxMACsPerPort = 256

const (
	sysObjectIDCisco  = "1.3.6.1.4.1.9."
	sysObjectIDHuawei = "1.3.6.1.4.1.2011."
)

// Column base OIDs (indexed by ifIndex). See RFC 2863 (IF-MIB),
// RFC 3635 (EtherLike-MIB). dot3StatsIndex equals ifIndex.
const (
	colIfDescr       = "1.3.6.1.2.1.2.2.1.2"
	colIfAdminStatus = "1.3.6.1.2.1.2.2.1.7"
	colIfOperStatus  = "1.3.6.1.2.1.2.2.1.8"
	colIfLastChange  = "1.3.6.1.2.1.2.2.1.9"
	colIfInErrors    = "1.3.6.1.2.1.2.2.1.14"
	colIfOutErrors   = "1.3.6.1.2.1.2.2.1.20"
	colIfName        = "1.3.6.1.2.1.31.1.1.1.1"
	colIfHCInOctets  = "1.3.6.1.2.1.31.1.1.1.6"
	colIfHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10"
	colIfHighSpeed   = "1.3.6.1.2.1.31.1.1.1.15"
	colIfAlias       = "1.3.6.1.2.1.31.1.1.1.18"
	colDot3Duplex    = "1.3.6.1.2.1.10.7.2.1.19"
)
