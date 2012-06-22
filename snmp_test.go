package snmp

import (
	asn1 "github.com/huin/asn1ber"
	"net"
	"testing"
)

func TestSNMPGetRequest(t *testing.T) {
	addr := net.UDPAddr{net.IPv4(192, 168, 1, 254), 161}
	s, err := GetStringValue([]int{1, 3, 6, 1, 2, 1, 1, 1, 0}, "timer", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(s)
}

func TestSNMPGetNextRequest(t *testing.T) {
	r := PDU{
		RequestId:   199,
		ErrorStatus: 0,
		ErrorIndex:  0,
		VarBindList: []VarBind{
			VarBind{
				Name:  []int{1, 3, 6, 1, 2, 1, 1, 1, 0},
				Value: Null(),
			},
		},
	}

	data, err := asn1.Marshal(r)
	if err != nil {
		t.Error(err)
	}

	m := Message{
		Version:   1,
		Community: NewOctetString("timer"),
		Data:      Any(data),
	}

	data, err = asn1.Marshal(m)
	if err != nil {
		t.Error(err)
	}

	addr := net.UDPAddr{net.IPv4(192, 168, 1, 254), 161}
	conn, err := net.DialUDP("udp4", nil, &addr)
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	written, err := conn.Write(data)
	if err != nil {
		t.Error(err)
	}

	if written != len(data) {
		t.Errorf("did not write the full data %d", written)
	}

}
