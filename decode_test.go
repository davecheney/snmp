package snmp

import (
	"testing"

	"github.com/davecheney/pcap"
)

func TestDecodeASN1(t *testing.T) {
	p, err := pcap.Open("testdata/snmp.pcap")
	if err != nil {
		t.Error(err)
	}
	defer p.Close()
	_, data, err := p.ReadPacket() // skip first packet, it's the request
	_, data, err = p.ReadPacket()
        if err != nil  {
                t.Error(err)
        }
	// 42 is the offset within the packet capture
	r, err := decode(data[42:]) 
	if err != nil {
		t.Error(err)
	}	
	_, ok := r.(Response)
	if !ok {
		t.Error("Type assertion failed")
	}
	
}
