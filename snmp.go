package snmp

import (
	"asn1"
	"net"
	"os"
	"fmt"
)

type OctetString []byte

type VarBind struct {
	Name asn1.ObjectIdentifier
	Value interface{}
}

type GetRequest struct {
	RequestId int32
	ErrorStatus int
	ErrorIndex int
	VarBindList []VarBind
}

type Message struct {
	Version int
	Community OctetString
	Data asn1.RawValue 
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
	full := make([]byte, len(bytes) +2)
	full[0] = 0
	// strip off the header from the original
	// request
	full[1] = uint8(len(bytes) -2)
	for i, b := range bytes[2:] {
		full[i + 2] = b
	}
	return asn1.RawValue{ 
		Class: 2, 
		Tag: 0,
	    IsCompound: true,
	    Bytes:	bytes[2:],
	    FullBytes: full,
	} 
}

// ASN1 NULL Value
func Null() asn1.RawValue {
	return asn1.RawValue {
		Class: 0,
		Tag: 5,
		IsCompound: false,
		Bytes: []byte { },
		FullBytes: []byte { 05, 00 },
	}
}

type GetNextRequest struct {
	RequestId int32
	ErrorStatus int
	ErrorIndex int
	VarBindList []VarBind
}

type Response struct {
	RequestId int32
	ErrorStatus int
	ErrorIndex int
//	VarBindList []VarBind
}

func GetStringValue(oid asn1.ObjectIdentifier, community string, addr net.UDPAddr) (string, os.Error) {
	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	
	r := GetRequest{
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
		return "", err
	}

	m := Message{
		Version: 1,
		Community: NewOctetString(community),
		Data: Any(data),
	}
	
	data, err = asn1.Marshal(m)
	if err != nil {
		return "", err
	}
	
	_, err = conn.Write(data)
	if err != nil {
		return "", err
	}
	
	data = make([]byte, 1500)
	read, err := conn.Read(data)
	if err != nil {
		return "", err
	}
	
	// return "", fmt.Errorf("%#v", data[:read])
	
	m = Message{}
	_, err = asn1.Unmarshal(data[:read], &m)
	if err != nil {
		return "", err
	}
	
	response := Response{}
	// hack ANY -> IMPLICIT SEQUENCE
	//m.Data.FullBytes[0] = 0x30
	// return "", fmt.Errorf("%#v", m.Data.FullBytes)
	_, err = asn1.Unmarshal(m.Data.FullBytes, &response)
	if err != nil {
		return "", fmt.Errorf("%#v, %#v, %s",m.Data.FullBytes, response, err)
	}
	
//	s, ok := response.VarBindList[0].Value.(string)
//	if !ok {
//		return "", fmt.Errorf("Invalid value returned")
//	}	
//	return s, nil
	return "", nil
}
