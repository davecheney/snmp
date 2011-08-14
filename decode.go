package snmp

import (
	"asn1"
	"fmt"
	"os"
)

func decode(data []byte) (interface{}, os.Error) {
	m := Message{}
	_, err := asn1.Unmarshal(data, &m)
	if err != nil {
		fmt.Errorf("%#v", data)
		return nil, err
	}
	choice := m.Data.FullBytes[0]
	switch choice {
	case 0xa0:
		// GetRequest
		request := new(GetRequest)
		// hack ANY -> IMPLICIT SEQUENCE
		m.Data.FullBytes[0] = 0x30
		_, err = asn1.Unmarshal(m.Data.FullBytes, request)
		if err != nil {
			return nil, fmt.Errorf("%#v, %#v, %s", m.Data.FullBytes, request, err)
		}
		return request, nil
	case 0xa1:
                // GetNextRequest
                request := new(GetRequest)
                // hack ANY -> IMPLICIT SEQUENCE
                m.Data.FullBytes[0] = 0x30
                _, err = asn1.Unmarshal(m.Data.FullBytes, request)
                if err != nil {
                        return nil, fmt.Errorf("%#v, %#v, %s", m.Data.FullBytes, request, err)
                }
                return request, nil
	
	case 0xa2:
		// Response
		response := new(Response)
		// hack ANY -> IMPLICIT SEQUENCE
		m.Data.FullBytes[0] = 0x30
		_, err = asn1.Unmarshal(m.Data.FullBytes, response)
		if err != nil {
			return nil, fmt.Errorf("%#v, %#v, %s", m.Data.FullBytes, response, err)
		}
		return response, nil
	default:
		return nil, fmt.Errorf("Unknown CHOICE: %x", choice)
	}
	panic("Unpossible!")
}
