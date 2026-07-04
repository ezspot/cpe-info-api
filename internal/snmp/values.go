package snmp

import (
	"strings"

	"github.com/gosnmp/gosnmp"
)

func isException(pdu gosnmp.SnmpPDU) bool {
	switch pdu.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		return true
	default:
		return pdu.Value == nil
	}
}

func pduString(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case []byte:
		return strings.TrimSpace(string(v))
	case string:
		return strings.TrimSpace(v)
	default:
		return ""
	}
}

func pduUint(pdu gosnmp.SnmpPDU) uint64 {
	if isException(pdu) {
		return 0
	}
	return gosnmp.ToBigInt(pdu.Value).Uint64()
}

func pduInt(pdu gosnmp.SnmpPDU) int64 {
	if isException(pdu) {
		return 0
	}
	return gosnmp.ToBigInt(pdu.Value).Int64()
}

func v3MsgFlags(level string) (gosnmp.SnmpV3MsgFlags, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "noauthnopriv":
		return gosnmp.NoAuthNoPriv | gosnmp.Reportable, nil
	case "authnopriv":
		return gosnmp.AuthNoPriv | gosnmp.Reportable, nil
	case "authpriv", "":
		return gosnmp.AuthPriv | gosnmp.Reportable, nil
	default:
		return 0, invalidV3("SNMP_V3_LEVEL", level)
	}
}

func v3AuthProtocol(name string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "", "NOAUTH", "NONE":
		return gosnmp.NoAuth, nil
	case "MD5":
		return gosnmp.MD5, nil
	case "SHA", "SHA1":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA256":
		return gosnmp.SHA256, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	default:
		return 0, invalidV3("SNMP_V3_AUTH_PROTOCOL", name)
	}
}

func v3PrivProtocol(name string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "", "NOPRIV", "NONE":
		return gosnmp.NoPriv, nil
	case "DES":
		return gosnmp.DES, nil
	case "AES", "AES128":
		return gosnmp.AES, nil
	case "AES192":
		return gosnmp.AES192, nil
	case "AES256":
		return gosnmp.AES256, nil
	case "AES192C":
		return gosnmp.AES192C, nil
	case "AES256C":
		return gosnmp.AES256C, nil
	default:
		return 0, invalidV3("SNMP_V3_PRIV_PROTOCOL", name)
	}
}
