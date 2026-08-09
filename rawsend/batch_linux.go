//go:build linux

package rawsend

import (
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

var sendmmsgAddr uintptr

// sendmmsgLoadOnce guards the lazy, one-time resolution of the sendmmsg libc
// symbol. The library is deliberately not loaded from an init() function so
// that merely importing this package never triggers a dlopen; resolution
// happens on first use (see ensureSendmmsg).
var sendmmsgLoadOnce sync.Once

// ensureSendmmsg resolves the sendmmsg symbol from libc exactly once. It is a
// no-op when sendmmsg is not available (e.g. musl or older glibc), in which
// case sendmmsgAddr stays 0 and callers degrade gracefully.
func ensureSendmmsg() {
	sendmmsgLoadOnce.Do(func() {
		libc, err := purego.Dlopen("libc.so.6", purego.RTLD_LAZY)
		if err != nil {
			return
		}
		addr, err := purego.Dlsym(libc, "sendmmsg")
		if err != nil {
			return
		}
		sendmmsgAddr = addr
	})
}

// mmsghdr mirrors C struct mmsghdr. Using unix.Msghdr ensures
// correct field sizes and alignment on both 32-bit and 64-bit Linux.
// Go's natural struct padding produces the correct trailing padding.
type mmsghdr struct {
	Hdr    unix.Msghdr
	MsgLen uint32
}

type sockaddrInet4Raw struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

// Batch accumulates raw IPv4 packets and sends them via a single
// sendmmsg syscall, amortising kernel-transition overhead across
// batchSize packets.
//
// Loaded via purego (no CGO).  NewBatch returns nil when sendmmsg
// is not available.
type Batch struct {
	fd        socketFD
	count     int
	batchSize int
	maxPktLen int
	pkts      []byte // flat buffer: batchSize * maxPktLen
	pktLens   []int  // actual length of each queued packet
	addrs     []sockaddrInet4Raw
	iovs      []unix.Iovec
	msgs      []mmsghdr
}

// NewBatch creates a batch sender that accumulates up to batchSize
// packets of at most maxPktLen bytes each, sending them all in one
// sendmmsg syscall.  Returns nil if sendmmsg is not available.
func NewBatch(fd socketFD, batchSize, maxPktLen int) *Batch {
	ensureSendmmsg()
	if sendmmsgAddr == 0 {
		return nil
	}
	b := &Batch{
		fd:        fd,
		batchSize: batchSize,
		maxPktLen: maxPktLen,
		pkts:      make([]byte, batchSize*maxPktLen),
		pktLens:   make([]int, batchSize),
		addrs:     make([]sockaddrInet4Raw, batchSize),
		iovs:      make([]unix.Iovec, batchSize),
		msgs:      make([]mmsghdr, batchSize),
	}
	for i := 0; i < batchSize; i++ {
		b.addrs[i].Family = syscall.AF_INET
		b.iovs[i].Base = &b.pkts[i*maxPktLen]
		b.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&b.addrs[i]))
		b.msgs[i].Hdr.Namelen = 16 // sizeof(sockaddr_in)
		b.msgs[i].Hdr.Iov = &b.iovs[i]
		b.msgs[i].Hdr.Iovlen = 1
	}
	return b
}

// Add copies pkt into the batch and sets the destination IPv4 address.
// When the batch is full, it is flushed automatically.
func (b *Batch) Add(pkt []byte, dstIP [4]byte) error {
	// A prior Flush may have left an unsent tail (congestion), so the batch can
	// already be full on entry. Drain it before appending so we never index past
	// the buffer; if the kernel is still saturated report the error rather than
	// overwriting queued-but-unsent packets.
	if b.count >= b.batchSize {
		if err := b.Flush(); err != nil {
			return err
		}
		if b.count >= b.batchSize {
			return syscall.EAGAIN
		}
	}
	i := b.count
	off := i * b.maxPktLen
	n := copy(b.pkts[off:off+b.maxPktLen], pkt)
	b.pktLens[i] = n
	b.iovs[i].SetLen(n)
	b.addrs[i].Addr = dstIP
	b.count++
	if b.count == b.batchSize {
		return b.Flush()
	}
	return nil
}

// Flush sends all queued packets via sendmmsg. If the kernel performs
// a partial send (fewer messages than requested), Flush retries the
// remaining messages. On a mid-batch error (typically ENOBUFS/EAGAIN when the
// qdisc is full) the still-unsent messages are compacted to the front of the
// batch and kept queued, so a caller that backs off re-sends them on the next
// Flush instead of silently dropping up to batchSize-1 probes.
func (b *Batch) Flush() error {
	if b.count == 0 {
		return nil
	}
	n := b.count

	sent := 0
	for sent < n {
		r1, _, errno := purego.SyscallN(
			sendmmsgAddr,
			uintptr(b.fd),
			uintptr(unsafe.Pointer(&b.msgs[sent])),
			uintptr(n-sent),
			0,
		)
		runtime.KeepAlive(b)
		// sendmmsg returns -1 on error; errno is only meaningful then.
		if int(r1) < 0 {
			b.keepUnsent(sent, n)
			return syscall.Errno(errno)
		}
		cnt := int(r1)
		if cnt == 0 {
			b.keepUnsent(sent, n)
			return syscall.EAGAIN
		}
		sent += cnt
	}
	b.count = 0
	return nil
}

// keepUnsent compacts the messages in [sent, n) to the front of the batch and
// sets count to the number kept, so the next Flush retransmits them. The iov
// Base pointers are pinned to fixed buffer offsets at construction, so only the
// packet bytes, lengths and destination addresses need to move.
func (b *Batch) keepUnsent(sent, n int) {
	if sent == 0 {
		b.count = n
		return
	}
	rem := n - sent
	for k := 0; k < rem; k++ {
		src := sent + k
		ln := b.pktLens[src]
		srcOff := src * b.maxPktLen
		dstOff := k * b.maxPktLen
		copy(b.pkts[dstOff:dstOff+ln], b.pkts[srcOff:srcOff+ln])
		b.pktLens[k] = ln
		b.iovs[k].SetLen(ln)
		b.addrs[k].Addr = b.addrs[src].Addr
	}
	b.count = rem
}

// Len returns the number of packets currently queued.
func (b *Batch) Len() int { return b.count }
