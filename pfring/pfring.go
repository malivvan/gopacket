// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pfring

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/malivvan/gopacket"
)

const errorBufferSize = 256

var pfringLoaded = false

var (
	pfringHandle  uintptr
	pfringLoadErr error
)

var (
	pfringOpenPtr,
	pfringClosePtr,
	pfringRecvPtr,
	pfringSetClusterPtr,
	pfringRemoveFromClusterPtr,
	pfringSetSamplingRatePtr,
	pfringSetPollWatermarkPtr,
	pfringConfigPtr,
	pfringSetPollDurationPtr,
	pfringSetBpfFilterPtr,
	pfringRemoveBpfFilterPtr,
	pfringSendPtr,
	pfringEnableRingPtr,
	pfringDisableRingPtr,
	pfringStatsPtr,
	pfringSetDirectionPtr,
	pfringSetSocketModePtr,
	pfringSetApplicationNamePtr,
	pfringVersionNoringPtr uintptr
)

func init() {
	loadPFRing()
}

func loadPFRing() error {
	if pfringLoaded {
		return pfringLoadErr
	}

	names := []string{
		"libpfring.so.1",
		"libpfring.so",
	}
	for _, name := range names {
		pfringHandle, pfringLoadErr = purego.Dlopen(name, purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if pfringLoadErr == nil {
			break
		}
	}
	if pfringLoadErr != nil {
		pfringLoadErr = fmt.Errorf("couldn't load libpfring: %w", pfringLoadErr)
		pfringLoaded = true
		return pfringLoadErr
	}

	pfringOpenPtr = mustLoadPfring("pfring_open")
	pfringClosePtr = mustLoadPfring("pfring_close")
	pfringRecvPtr = mustLoadPfring("pfring_recv")
	pfringSetClusterPtr = mustLoadPfring("pfring_set_cluster")
	pfringRemoveFromClusterPtr = mustLoadPfring("pfring_remove_from_cluster")
	pfringSetSamplingRatePtr = mustLoadPfring("pfring_set_sampling_rate")
	pfringSetPollWatermarkPtr = mustLoadPfring("pfring_set_poll_watermark")
	pfringConfigPtr = mustLoadPfring("pfring_config")
	pfringSetPollDurationPtr = mustLoadPfring("pfring_set_poll_duration")
	pfringSetBpfFilterPtr = mustLoadPfring("pfring_set_bpf_filter")
	pfringRemoveBpfFilterPtr = mustLoadPfring("pfring_remove_bpf_filter")
	pfringSendPtr = mustLoadPfring("pfring_send")
	pfringEnableRingPtr = mustLoadPfring("pfring_enable_ring")
	pfringDisableRingPtr = mustLoadPfring("pfring_disable_ring")
	pfringStatsPtr = mustLoadPfring("pfring_stats")
	pfringSetDirectionPtr = mustLoadPfring("pfring_set_direction")
	pfringSetSocketModePtr = mustLoadPfring("pfring_set_socket_mode")
	pfringSetApplicationNamePtr = mustLoadPfring("pfring_set_application_name")

	// The layout of pfring_extended_pkthdr changed in PF_RING 7.8.0
	// (port_id/device_id fields were inserted before if_index), so pick the
	// right field offsets based on the loaded library version.
	pfringVersionNoringPtr, _ = purego.Dlsym(pfringHandle, "pfring_version_noring")
	if pfringVersionNoringPtr != 0 {
		var version uint32
		purego.SyscallN(pfringVersionNoringPtr, uintptr(unsafe.Pointer(&version)))
		setPkthdrOffsetsForVersion(version)
	}

	pfringLoaded = true
	return nil
}

func mustLoadPfring(name string) uintptr {
	sym, err := purego.Dlsym(pfringHandle, name)
	if err != nil {
		panic(fmt.Sprintf("couldn't load function %s from libpfring: %v", name, err))
	}
	return sym
}

// Ring provides a handle to a pf_ring.
type Ring struct {
	cptr                    uintptr
	useExtendedPacketHeader bool
	interfaceIndex          int
	mu                      sync.Mutex

	bufPtr *uint8
}

// Flag provides a set of boolean flags to use when creating a new ring.
type Flag uint32

// Set of flags that can be passed (OR'd together) to NewRing.
const (
	FlagReentrant       Flag = flagReentrant
	FlagLongHeader      Flag = flagLongHeader
	FlagPromisc         Flag = flagPromisc
	FlagDNASymmetricRSS Flag = flagDNASymmetricRSS
	FlagTimestamp       Flag = flagTimestamp
	FlagHWTimestamp     Flag = flagHWTimestamp
)

// NewRing creates a new PFRing.  Note that when the ring is initially created,
// it is disabled.  The caller must call Enable to start receiving packets.
// The caller should call Close on the given ring when finished with it.
func NewRing(device string, snaplen uint32, flags Flag) (ring *Ring, _ error) {
	if err := loadPFRing(); err != nil {
		return nil, err
	}

	dev, err := syscall.BytePtrFromString(device)
	if err != nil {
		return nil, err
	}

	cptr, _, _ := purego.SyscallN(pfringOpenPtr,
		uintptr(unsafe.Pointer(dev)),
		uintptr(snaplen),
		uintptr(flags),
	)
	if cptr == 0 {
		return nil, fmt.Errorf("pfring NewRing error: pfring_open returned nil")
	}
	ring = &Ring{cptr: cptr}

	if flags&FlagLongHeader == FlagLongHeader {
		ring.useExtendedPacketHeader = true
	} else {
		ifc, err := net.InterfaceByName(device)
		if err == nil {
			ring.interfaceIndex = ifc.Index
		}
	}
	ring.SetApplicationName(os.Args[0])
	return
}

// Close closes the given Ring.  After this call, the Ring should no longer be
// used.
func (r *Ring) Close() {
	purego.SyscallN(pfringClosePtr, r.cptr)
}

// NextResult is the return code from a call to Next.
type NextResult int32

// Set of results that could be returned from a call to get another packet.
const (
	NextNoPacketNonblocking NextResult = 0
	NextError               NextResult = -1
	NextOk                  NextResult = 1
	NextNotEnabled          NextResult = -7
)

// NextResult implements the error interface.
func (n NextResult) Error() string {
	switch n {
	case NextNoPacketNonblocking:
		return "No packet available, nonblocking socket"
	case NextError:
		return "Generic error"
	case NextOk:
		return "Success (not an error)"
	case NextNotEnabled:
		return "Ring not enabled"
	}
	return strconv.Itoa(int(n))
}

// getNextBufPtrLocked fetches a packet + metadata from pf_ring.
// It calls pfring_recv directly and parses the packed pfring_pkthdr at
// known byte offsets, replacing the old C wrapper that existed to handle
// the packed struct incompatibility with Go.
func (r *Ring) getNextBufPtrLocked(ci *gopacket.CaptureInfo) error {
	var hdr [pfringPkthdrBufSize]byte
	result, _, _ := purego.SyscallN(pfringRecvPtr,
		r.cptr,
		uintptr(unsafe.Pointer(&r.bufPtr)),
		0,
		uintptr(unsafe.Pointer(&hdr[0])),
		1,
	)
	if NextResult(int32(result)) != NextOk {
		return NextResult(int32(result))
	}
	ci.Timestamp = time.Unix(0, int64(binary.NativeEndian.Uint64(hdr[offsetTsNs:])))
	ci.CaptureLength = int(binary.NativeEndian.Uint32(hdr[offsetCaplen:]))
	ci.Length = int(binary.NativeEndian.Uint32(hdr[offsetLen:]))
	if r.useExtendedPacketHeader {
		ci.InterfaceIndex = int(int32(binary.NativeEndian.Uint32(hdr[offsetIfIndex:])))
	} else {
		ci.InterfaceIndex = r.interfaceIndex
	}
	return nil
}

// ReadPacketDataTo reads packet data into a user-supplied buffer.
//
// Deprecated: This function is provided for legacy code only. Use ReadPacketData or ZeroCopyReadPacketData
// This function does an additional copy, and is therefore slower than ZeroCopyReadPacketData.
// The old implementation did the same inside the pf_ring library.
func (r *Ring) ReadPacketDataTo(data []byte) (ci gopacket.CaptureInfo, err error) {
	r.mu.Lock()
	err = r.getNextBufPtrLocked(&ci)
	if err == nil {
		var buf []byte
		slice := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
		slice.Data = uintptr(unsafe.Pointer(r.bufPtr))
		slice.Len = ci.CaptureLength
		slice.Cap = ci.CaptureLength
		copy(data, buf)
	}
	r.mu.Unlock()
	return
}

// ReadPacketData returns the next packet read from pf_ring, along with an error
// code associated with that packet. If the packet is read successfully, the
// returned error is nil.
func (r *Ring) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	r.mu.Lock()
	err = r.getNextBufPtrLocked(&ci)
	if err == nil {
		data = make([]byte, ci.CaptureLength)
		copy(data, unsafe.Slice(r.bufPtr, ci.CaptureLength))
	}
	r.mu.Unlock()
	return
}

// ZeroCopyReadPacketData returns the next packet read from pf_ring, along with an error
// code associated with that packet.
// The slice returned by ZeroCopyReadPacketData points to bytes inside a pf_ring
// ring. Each call to ZeroCopyReadPacketData might invalidate any data previously
// returned by ZeroCopyReadPacketData. Care must be taken not to keep pointers
// to old bytes when using ZeroCopyReadPacketData... if you need to keep data past
// the next time you call ZeroCopyReadPacketData, use ReadPacketData, which copies
// the bytes into a new buffer for you.
//
//	data1, _, _ := handle.ZeroCopyReadPacketData()
//	// do everything you want with data1 here, copying bytes out of it if you'd like to keep them around.
//	data2, _, _ := handle.ZeroCopyReadPacketData()  // invalidates bytes in data1
func (r *Ring) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	r.mu.Lock()
	err = r.getNextBufPtrLocked(&ci)
	if err == nil {
		slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))
		slice.Data = uintptr(unsafe.Pointer(r.bufPtr))
		slice.Len = ci.CaptureLength
		slice.Cap = ci.CaptureLength
	}
	r.mu.Unlock()
	return
}

// ClusterType is a type of clustering used when balancing across multiple
// rings.
type ClusterType int32

const (
	// ClusterPerFlow clusters by <src ip, src port, dst ip, dst port, proto,
	// vlan>
	ClusterPerFlow ClusterType = clusterPerFlow
	// ClusterRoundRobin round-robins packets between applications, ignoring
	// packet information.
	ClusterRoundRobin ClusterType = clusterRoundRobin
	// ClusterPerFlow2Tuple clusters by <src ip, dst ip>
	ClusterPerFlow2Tuple ClusterType = clusterPerFlow2Tuple
	// ClusterPerFlow4Tuple clusters by <src ip, src port, dst ip, dst port>
	ClusterPerFlow4Tuple ClusterType = clusterPerFlow4Tuple
	// ClusterPerFlow5Tuple clusters by <src ip, src port, dst ip, dst port,
	// proto>
	ClusterPerFlow5Tuple ClusterType = clusterPerFlow5Tuple
	// ClusterPerFlowTCP5Tuple acts like ClusterPerFlow5Tuple for TCP packets and
	// like ClusterPerFlow2Tuple for all other packets.
	ClusterPerFlowTCP5Tuple ClusterType = clusterPerFlowTCP5Tuple
)

// SetCluster sets which cluster the ring should be part of, and the cluster
// type to use.
func (r *Ring) SetCluster(cluster int, typ ClusterType) error {
	rv, _, _ := purego.SyscallN(pfringSetClusterPtr, r.cptr, uintptr(cluster), uintptr(typ))
	if int32(rv) != 0 {
		return fmt.Errorf("Unable to set cluster, got error code %d", int32(rv))
	}
	return nil
}

// RemoveFromCluster removes the ring from the cluster it was put in with
// SetCluster.
func (r *Ring) RemoveFromCluster() error {
	rv, _, _ := purego.SyscallN(pfringRemoveFromClusterPtr, r.cptr)
	if int32(rv) != 0 {
		return fmt.Errorf("Unable to remove from cluster, got error code %d", int32(rv))
	}
	return nil
}

// SetSamplingRate sets the sampling rate to 1/<rate>.
func (r *Ring) SetSamplingRate(rate int) error {
	rv, _, _ := purego.SyscallN(pfringSetSamplingRatePtr, r.cptr, uintptr(rate))
	if int32(rv) != 0 {
		return fmt.Errorf("Unable to set sampling rate, got error code %d", int32(rv))
	}
	return nil
}

// SetPollWatermark sets the pfring's poll watermark packet count
func (r *Ring) SetPollWatermark(count uint16) error {
	rv, _, _ := purego.SyscallN(pfringSetPollWatermarkPtr, r.cptr, uintptr(count))
	if int32(rv) != 0 {
		return fmt.Errorf("Unable to set poll watermark, got error code %d", int32(rv))
	}
	return nil
}

// SetPriority sets the pfring poll threads CPU usage limit
func (r *Ring) SetPriority(cpu uint16) {
	purego.SyscallN(pfringConfigPtr, uintptr(cpu))
}

// SetPollDuration sets the pfring's poll duration before it yields/returns
func (r *Ring) SetPollDuration(durationMillis uint) error {
	rv, _, _ := purego.SyscallN(pfringSetPollDurationPtr, r.cptr, uintptr(durationMillis))
	if int32(rv) != 0 {
		return fmt.Errorf("Unable to set poll duration, got error code %d", int32(rv))
	}
	return nil
}

// SetBPFFilter sets the BPF filter for the ring.
func (r *Ring) SetBPFFilter(bpfFilter string) error {
	filter, err := syscall.BytePtrFromString(bpfFilter)
	if err != nil {
		return err
	}
	rv, _, _ := purego.SyscallN(pfringSetBpfFilterPtr, r.cptr, uintptr(unsafe.Pointer(filter)))
	if int32(rv) != 0 {
		return fmt.Errorf("Unable to set BPF filter, got error code %d", int32(rv))
	}
	return nil
}

// RemoveBPFFilter removes the BPF filter from the ring.
func (r *Ring) RemoveBPFFilter() error {
	rv, _, _ := purego.SyscallN(pfringRemoveBpfFilterPtr, r.cptr)
	if int32(rv) != 0 {
		return fmt.Errorf("Unable to remove BPF filter, got error code %d", int32(rv))
	}
	return nil
}

// WritePacketData uses the ring to send raw packet data to the interface.
func (r *Ring) WritePacketData(data []byte) error {
	rv, _, _ := purego.SyscallN(pfringSendPtr,
		r.cptr,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		1,
	)
	if int32(rv) < 0 {
		return fmt.Errorf("Unable to send packet data, got error code %d", int32(rv))
	}
	return nil
}

// Enable enables the given ring.  This function MUST be called on each new
// ring after it has been set up, or that ring will NOT receive packets.
func (r *Ring) Enable() error {
	rv, _, _ := purego.SyscallN(pfringEnableRingPtr, r.cptr)
	if int32(rv) != 0 {
		return fmt.Errorf("Unable to enable ring, got error code %d", int32(rv))
	}
	return nil
}

// Disable disables the given ring.  After this call, it will no longer receive
// packets.
func (r *Ring) Disable() error {
	rv, _, _ := purego.SyscallN(pfringDisableRingPtr, r.cptr)
	if int32(rv) != 0 {
		return fmt.Errorf("Unable to disable ring, got error code %d", int32(rv))
	}
	return nil
}

// Stats provides simple statistics on a ring.
type Stats struct {
	Received, Dropped uint64
}

// Stats returns statistsics for the ring.
func (r *Ring) Stats() (s Stats, err error) {
	var stats pfringStats
	rv, _, _ := purego.SyscallN(pfringStatsPtr, r.cptr, uintptr(unsafe.Pointer(&stats)))
	if int32(rv) != 0 {
		err = fmt.Errorf("Unable to get ring stats, got error code %d", int32(rv))
		return
	}
	s.Received = stats.Recv
	s.Dropped = stats.Drop
	return
}

// Direction is a simple enum to set which packets (TX, RX, or both) a ring
// captures.
type Direction int32

const (
	// TransmitOnly will only capture packets transmitted by the ring's
	// interface(s).
	TransmitOnly Direction = txOnlyDirection
	// ReceiveOnly will only capture packets received by the ring's
	// interface(s).
	ReceiveOnly Direction = rxOnlyDirection
	// ReceiveAndTransmit will capture both received and transmitted packets on
	// the ring's interface(s).
	ReceiveAndTransmit Direction = rxAndTxDirection
)

// SetDirection sets which packets should be captured by the ring.
func (r *Ring) SetDirection(d Direction) error {
	rv, _, _ := purego.SyscallN(pfringSetDirectionPtr, r.cptr, uintptr(d))
	if int32(rv) != 0 {
		return fmt.Errorf("Unable to set ring direction, got error code %d", int32(rv))
	}
	return nil
}

// SocketMode is an enum for setting whether a ring should read, write, or both.
type SocketMode int32

const (
	// WriteOnly sets up the ring to only send packets (Inject), not read them.
	WriteOnly SocketMode = sendOnlyMode
	// ReadOnly sets up the ring to only receive packets (ReadPacketData), not
	// send them.
	ReadOnly SocketMode = recvOnlyMode
	// WriteAndRead sets up the ring to both send and receive packets.
	WriteAndRead SocketMode = sendAndRecvMode
)

// SetSocketMode sets the mode of the ring socket to send, receive, or both.
func (r *Ring) SetSocketMode(s SocketMode) error {
	rv, _, _ := purego.SyscallN(pfringSetSocketModePtr, r.cptr, uintptr(s))
	if int32(rv) != 0 {
		return fmt.Errorf("Unable to set socket mode, got error code %d", int32(rv))
	}
	return nil
}

// SetApplicationName sets a string name to the ring.  This name is available in
// /proc stats for pf_ring.  By default, NewRing automatically calls this with
// argv[0].
func (r *Ring) SetApplicationName(name string) error {
	buf, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	rv, _, _ := purego.SyscallN(pfringSetApplicationNamePtr, r.cptr, uintptr(unsafe.Pointer(buf)))
	if int32(rv) != 0 {
		return fmt.Errorf("Unable to set ring application name, got error code %d", int32(rv))
	}
	return nil
}
