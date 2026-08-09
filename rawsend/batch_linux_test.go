//go:build linux

package rawsend

import (
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestMmsghdrSize(t *testing.T) {
	got := unsafe.Sizeof(mmsghdr{})
	msghdrSize := unsafe.Sizeof(unix.Msghdr{})
	ptrSize := unsafe.Sizeof(uintptr(0))

	// mmsghdr = Msghdr + uint32(MsgLen) + padding to pointer alignment
	// 64-bit: 56 + 4 + 4(pad) = 64
	// 32-bit: 28 + 4 = 32
	expected := msghdrSize + 4
	if remainder := expected % ptrSize; remainder != 0 {
		expected += ptrSize - remainder
	}
	if got != expected {
		t.Errorf("sizeof(mmsghdr) = %d, want %d (sizeof(Msghdr)=%d, ptrSize=%d)",
			got, expected, msghdrSize, ptrSize)
	}
}

func TestSockaddrInet4RawSize(t *testing.T) {
	got := unsafe.Sizeof(sockaddrInet4Raw{})
	if got != 16 {
		t.Errorf("sizeof(sockaddrInet4Raw) = %d, want 16", got)
	}
}

func TestNewBatchNilWhenUnavailable(t *testing.T) {
	ensureSendmmsg() // trigger the one-time lazy resolution so the zeroing below sticks
	orig := sendmmsgAddr
	sendmmsgAddr = 0
	defer func() { sendmmsgAddr = orig }()

	b := NewBatch(3, 10, 64)
	if b != nil {
		t.Error("expected nil when sendmmsg not available")
	}
}

func TestNewBatchCreation(t *testing.T) {
	ensureSendmmsg()
	if sendmmsgAddr == 0 {
		t.Skip("sendmmsg not available")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer syscall.Close(fd)

	b := NewBatch(fd, 8, 128)
	if b == nil {
		t.Fatal("NewBatch returned nil")
	}
	if b.Len() != 0 {
		t.Errorf("new batch Len() = %d, want 0", b.Len())
	}
	if b.batchSize != 8 {
		t.Errorf("batchSize = %d, want 8", b.batchSize)
	}
	if b.maxPktLen != 128 {
		t.Errorf("maxPktLen = %d, want 128", b.maxPktLen)
	}
}

func TestBatchFlushEmpty(t *testing.T) {
	ensureSendmmsg()
	if sendmmsgAddr == 0 {
		t.Skip("sendmmsg not available")
	}
	b := NewBatch(3, 10, 64)
	if b == nil {
		t.Fatal("NewBatch returned nil")
	}
	if err := b.Flush(); err != nil {
		t.Errorf("Flush on empty batch: %v", err)
	}
}

func TestBatchAddIncrementsCount(t *testing.T) {
	ensureSendmmsg()
	if sendmmsgAddr == 0 {
		t.Skip("sendmmsg not available")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer syscall.Close(fd)

	batchSize := 5
	b := NewBatch(fd, batchSize, 64)
	if b == nil {
		t.Fatal("NewBatch returned nil")
	}

	pkt := []byte("hello")
	dst := [4]byte{127, 0, 0, 1}

	for i := 0; i < batchSize-1; i++ {
		if err := b.Add(pkt, dst); err != nil {
			t.Fatalf("Add[%d]: %v", i, err)
		}
		if b.Len() != i+1 {
			t.Errorf("after Add[%d], Len() = %d, want %d", i, b.Len(), i+1)
		}
	}
}

func TestBatchIovecSetup(t *testing.T) {
	ensureSendmmsg()
	if sendmmsgAddr == 0 {
		t.Skip("sendmmsg not available")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer syscall.Close(fd)

	b := NewBatch(fd, 4, 128)
	if b == nil {
		t.Fatal("NewBatch returned nil")
	}

	pkt := []byte("test-packet-data")
	dst := [4]byte{10, 0, 0, 1}
	if err := b.Add(pkt, dst); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Verify the iovec length was set correctly
	iov := b.iovs[0]
	var iovLen int
	iovLen = int(*(*uint32)(unsafe.Pointer(&iov.Len)))
	if unsafe.Sizeof(uintptr(0)) == 8 {
		iovLen = int(*(*uint64)(unsafe.Pointer(&iov.Len)))
	}
	if iovLen != len(pkt) {
		t.Errorf("iov.Len = %d, want %d", iovLen, len(pkt))
	}

	// Verify destination address was set
	if b.addrs[0].Addr != dst {
		t.Errorf("addr = %v, want %v", b.addrs[0].Addr, dst)
	}
	if b.addrs[0].Family != syscall.AF_INET {
		t.Errorf("family = %d, want %d", b.addrs[0].Family, syscall.AF_INET)
	}
}

func TestBatchSendReceiveRaw(t *testing.T) {
	ensureSendmmsg()
	if sendmmsgAddr == 0 {
		t.Skip("sendmmsg not available")
	}
	// Raw sockets require CAP_NET_RAW
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		t.Skipf("skipping (needs root/CAP_NET_RAW): %v", err)
	}
	defer syscall.Close(fd)

	b := NewBatch(fd, 4, 128)
	if b == nil {
		t.Fatal("NewBatch returned nil")
	}

	// ICMP echo request: type=8, code=0, checksum, id, seq
	mkICMP := func(seq byte) []byte {
		pkt := []byte{8, 0, 0, 0, 0, 1, 0, seq}
		var sum uint32
		for i := 0; i < len(pkt)-1; i += 2 {
			sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
		}
		sum = (sum >> 16) + (sum & 0xffff)
		sum += sum >> 16
		cs := ^uint16(sum)
		pkt[2] = byte(cs >> 8)
		pkt[3] = byte(cs)
		return pkt
	}

	lo := [4]byte{127, 0, 0, 1}
	for i := byte(1); i <= 3; i++ {
		if err := b.Add(mkICMP(i), lo); err != nil {
			t.Fatalf("Add[%d]: %v", i, err)
		}
	}
	if b.Len() != 3 {
		t.Errorf("Len() = %d, want 3", b.Len())
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if b.Len() != 0 {
		t.Errorf("after Flush, Len() = %d, want 0", b.Len())
	}
}

func TestBatchKeepUnsentCompaction(t *testing.T) {
	batchSize, maxPktLen := 4, 8
	b := &Batch{
		batchSize: batchSize,
		maxPktLen: maxPktLen,
		pkts:      make([]byte, batchSize*maxPktLen),
		pktLens:   make([]int, batchSize),
		addrs:     make([]sockaddrInet4Raw, batchSize),
		iovs:      make([]unix.Iovec, batchSize),
		msgs:      make([]mmsghdr, batchSize),
	}
	for i := 0; i < batchSize; i++ {
		b.iovs[i].Base = &b.pkts[i*maxPktLen]
	}
	// Queue 4 packets, each a single distinct byte with a distinct dst.
	for i := 0; i < batchSize; i++ {
		b.pkts[i*maxPktLen] = byte(i + 1)
		b.pktLens[i] = 1
		b.iovs[i].SetLen(1)
		b.addrs[i].Addr = [4]byte{byte(i), 0, 0, 1}
	}
	b.count = batchSize

	// Simulate the first two messages sent; the tail [2,4) must move to front.
	b.keepUnsent(2, 4)
	if b.count != 2 {
		t.Fatalf("count = %d, want 2", b.count)
	}
	if b.pkts[0] != 3 || b.pkts[maxPktLen] != 4 {
		t.Fatalf("compacted bytes = %d,%d, want 3,4", b.pkts[0], b.pkts[maxPktLen])
	}
	if b.pktLens[0] != 1 || b.pktLens[1] != 1 {
		t.Fatalf("compacted lens = %d,%d, want 1,1", b.pktLens[0], b.pktLens[1])
	}
	if b.addrs[0].Addr != ([4]byte{2, 0, 0, 1}) || b.addrs[1].Addr != ([4]byte{3, 0, 0, 1}) {
		t.Fatalf("compacted addrs = %v,%v", b.addrs[0].Addr, b.addrs[1].Addr)
	}

	// sent == 0 means nothing progressed: the whole batch stays queued.
	b.count = batchSize
	b.keepUnsent(0, batchSize)
	if b.count != batchSize {
		t.Fatalf("keepUnsent(0,n) count = %d, want %d", b.count, batchSize)
	}
}

func TestBatchAutoFlush(t *testing.T) {
	ensureSendmmsg()
	if sendmmsgAddr == 0 {
		t.Skip("sendmmsg not available")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		t.Skipf("skipping (needs root/CAP_NET_RAW): %v", err)
	}
	defer syscall.Close(fd)

	batchSize := 3
	b := NewBatch(fd, batchSize, 128)
	if b == nil {
		t.Fatal("NewBatch returned nil")
	}

	mkICMP := func(seq byte) []byte {
		pkt := []byte{8, 0, 0, 0, 0, 1, 0, seq}
		var sum uint32
		for i := 0; i < len(pkt)-1; i += 2 {
			sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
		}
		sum = (sum >> 16) + (sum & 0xffff)
		sum += sum >> 16
		cs := ^uint16(sum)
		pkt[2] = byte(cs >> 8)
		pkt[3] = byte(cs)
		return pkt
	}

	lo := [4]byte{127, 0, 0, 1}
	// Adding exactly batchSize packets should trigger auto-flush
	for i := byte(1); i <= byte(batchSize); i++ {
		if err := b.Add(mkICMP(i), lo); err != nil {
			t.Fatalf("Add[%d]: %v", i, err)
		}
	}
	// After auto-flush, count should be 0
	if b.Len() != 0 {
		t.Errorf("after auto-flush, Len() = %d, want 0", b.Len())
	}
}
