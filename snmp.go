package snmp

import (
	"fmt"
	"net"

	asn1 "github.com/huin/asn1ber"
)

type OctetString []byte

type Message struct {
	Version   int
	Community OctetString
	Data      asn1.RawValue
}

func NewOctetString(s string) OctetString {
	b := make([]byte, len(s))
	for i, c := range s {
		b[i] = byte(c)
	}
	return b
}

// Constuct a RawValue type ANY
func Any(bytes []byte) asn1.RawValue {
	return asn1.RawValue{
		Class:      2,
		Tag:        0,
		IsCompound: true,
		Bytes:      bytes[2:],
	}
}

// ASN1 NULL Value
func Null() asn1.RawValue {
	return asn1.RawValue{
		Class:      0,
		Tag:        5,
		IsCompound: false,
		Bytes:      []byte{},
	}
}

func GetValue(oid asn1.ObjectIdentifier, community string, addr net.UDPAddr) (interface{}, error) {
	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	r := PDU{
		RequestId:   199,
		ErrorStatus: 0,
		ErrorIndex:  0,
		VarBindList: []VarBind{
			VarBind{
				Name:  oid,
				Value: Null(),
			},
		},
	}

	data, err := asn1.Marshal(r)
	if err != nil {
		return nil, err
	}

	m := Message{
		Version:   1,
		Community: NewOctetString(community),
		Data:      Any(data),
	}

	data, err = asn1.Marshal(m)
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(data)
	if err != nil {
		return nil, err
	}

	data = make([]byte, 1500)
	read, err := conn.Read(data)
	if err != nil {
		return nil, err
	}

	pdu, err := decode(data[:read])
	if err != nil {
		return nil, err
	}
	switch response := pdu.(type) {
	case *PDU:
		return parseVarValue(response.VarBindList[0].Value)
	}
	return nil, nil
}

func GetStringValue(oid asn1.ObjectIdentifier, community string, addr net.UDPAddr) (string, error) {
	value, err := GetValue(oid, community, addr)
	if err != nil {
		return "", err
	}
	s, ok := value.([]byte)
	if !ok {
		return "", fmt.Errorf("Invalid value returned, got %#v", value)
	}
	return string(s), nil
}

// SNMP Application specific tags.
const (
	TagIPAddress  = 0
	TagCounter32  = 1
	TagGauge32    = 2
	TagUnsigned32 = TagGauge32
	TagTimeTicks  = 3
	TagOpaque     = 4
	TagCounter64  = 6
)

type (
	Counter32 uint32
	Gauge32   uint32
	TimeTicks uint32
	Opaque    []byte
	Counter64 uint64
)

func parseVarValue(rv asn1.RawValue) (value interface{}, err error) {
	switch rv.Class {
	case asn1.ClassUniversal:
		_, err = asn1.Unmarshal(rv.FullBytes, &value)
		return
	case asn1.ClassApplication:
		switch rv.Tag {
		case TagCounter32:
			var v uint32
			v, err = asn1.ParseUint32(rv.Bytes)
			return Counter32(v), err
		case TagGauge32:
			var v uint32
			v, err = asn1.ParseUint32(rv.Bytes)
			return Gauge32(v), err
		case TagTimeTicks:
			var v uint32
			v, err = asn1.ParseUint32(rv.Bytes)
			return TimeTicks(v), err
		case TagOpaque:
			return Opaque(rv.Bytes), err
		case TagCounter64:
			var v uint64
			v, err = asn1.ParseUint64(rv.Bytes)
			return Counter64(v), err
		default:
			err = fmt.Errorf("Unknown application class tag %d", rv.Tag)
		}
	default:
		err = fmt.Errorf("Unknown var value class %d", rv.Class)
	}
	return
}
