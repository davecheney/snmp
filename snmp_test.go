package snmp

import (
	"testing"
	"asn1"
	"net"
)

func TestSNMPGetNextRequest(t *testing.T) {
	m := Message{
		Version: 1,
		Community: NewOctetString("timer"),
		Data: GetNextRequest{
				RequestId:   199,
				ErrorStatus: 0,
				ErrorIndex:  0,
				VarBindList: []VarBind{
					VarBind{
						Name:  []int{1, 3, 6, 1, 2, 1},
						Value: "",
					},
				},
		},
	}
	
	data, err := asn1.Marshal(m)
	if err != nil {
		t.Error(err)
	}
	
	addr := net.UDPAddr{ net.IPv4(192,168,1,254), 161}
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
		t.Error("did not write the full data")
	}
}
