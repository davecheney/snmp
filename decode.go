package snmp

import (
	"fmt"

	asn1 "github.com/huin/asn1ber"
)

func decode(data []byte) (interface{}, error) {
	m := Message{}
	_, err := asn1.Unmarshal(data, &m)
	if err != nil {
		return nil, fmt.Errorf("error in message decode: %v", err)
	}
	// Response
	pdu := new(PDU)
	// hack ANY -> IMPLICIT SEQUENCE
	m.Data.FullBytes[0] = 0x30
	_, err = asn1.Unmarshal(m.Data.FullBytes, pdu)
	if err != nil {
		return nil, fmt.Errorf("error in PDU decode: %v, %#v", err, m.Data.FullBytes, pdu)
	}
	return pdu, nil
}
