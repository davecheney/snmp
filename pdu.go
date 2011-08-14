package snmp

import (
	"asn1"
)

type VarBind struct {
	Name  asn1.ObjectIdentifier
	Value interface{}
}

type PDU struct {
	RequestId   int32
	ErrorStatus int
	ErrorIndex  int
	VarBindList []VarBind
}

