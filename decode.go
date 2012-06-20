package snmp

import (
	"encoding/asn1"
	"fmt"
)

func decode(data []byte) (interface{}, error) {
	m := Message{}
	_, err := asn1.Unmarshal(data, &m)
	if err != nil {
		fmt.Errorf("%#v", data)
		return nil, err
	}
	choice := m.Data.FullBytes[0]
	switch choice {
	case 0xa0, 0xa1, 0xa2:
		// Response
		pdu := new(PDU)
		// hack ANY -> IMPLICIT SEQUENCE
		m.Data.FullBytes[0] = 0x30
		_, err = asn1.Unmarshal(m.Data.FullBytes, pdu)
		if err != nil {
			return nil, fmt.Errorf("%#v, %#v, %s", m.Data.FullBytes, pdu, err)
		}
		return pdu, nil
	}
	return nil, fmt.Errorf("Unknown CHOICE: %x", choice)
}
