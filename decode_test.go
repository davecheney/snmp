package snmp

import (
	"testing"
	"os"

	"github.com/davecheney/pcap"
)

func TestDecodeASN1(t *testing.T) {
	p, err := pcap.Open("testdata/snmp.pcap")
	if err != nil {
		t.Error(err)
	}
	defer p.Close()
	for {
		_, data, err := p.ReadPacket()
		if err != nil {
			if err == os.EOF {
				return
			}
			t.Fatal(err)
		}
		// 42 is the offset within the packet capture
		packet, err := decode(data[42:])
		if err != nil {
			t.Fatal(err)
		}
		switch pdu := packet.(type) {
		case *PDU:
			t.Logf("%#v", pdu)
		default:
			t.Fatalf("Unknown pdu: %#v", pdu)
		}
	}

}
