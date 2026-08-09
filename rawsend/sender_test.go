package rawsend

import (
	"net"
	"testing"
)

func TestNewFromFD(t *testing.T) {
	conn, _ := net.ListenIP("ip4:1", nil)
	s := NewFromFD(socketFD(42), conn)
	if s == nil {
		t.Fatal("NewFromFD returned nil")
	}
	if s.FD() != socketFD(42) {
		t.Errorf("FD() = %v, want 42", s.FD())
	}
}

func TestNewFromIPConn(t *testing.T) {
	conn, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("skipping (needs root): %v", err)
	}
	defer conn.Close()

	s, err := NewFromIPConn(conn)
	if err != nil {
		t.Fatalf("NewFromIPConn: %v", err)
	}
	if s.FD() <= 0 {
		t.Errorf("expected positive FD, got %d", s.FD())
	}
}

func TestSenderSendTo(t *testing.T) {
	conn, err := net.ListenIP("ip4:icmp", &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("skipping (needs root): %v", err)
	}
	defer conn.Close()

	s, err := NewFromIPConn(conn)
	if err != nil {
		t.Fatalf("NewFromIPConn: %v", err)
	}

	// Craft a minimal ICMP echo request (type=8, code=0)
	pkt := []byte{
		8, 0, // type=echo, code=0
		0, 0, // checksum (kernel may fill)
		0, 1, // identifier
		0, 1, // sequence
	}
	// Compute ICMP checksum
	var sum uint32
	for i := 0; i < len(pkt)-1; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	cs := ^uint16(sum)
	pkt[2] = byte(cs >> 8)
	pkt[3] = byte(cs)

	err = s.SendTo(pkt, [4]byte{127, 0, 0, 1})
	if err != nil {
		t.Errorf("SendTo: %v", err)
	}
}
