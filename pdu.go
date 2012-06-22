package snmp

import (
	asn1 "github.com/huin/asn1ber"
)

type VarBind struct {
	Name  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type PDU struct {
	RequestId   int32
	ErrorStatus int
	ErrorIndex  int
	VarBindList []VarBind
}
