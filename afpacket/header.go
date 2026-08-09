// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build linux
// +build linux

package afpacket

import (
	"reflect"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Our model of handling all TPacket versions is a little hacky, to say the
// least.  We use the header interface to handle interactions with the
// tpacket1/tpacket2 packet header AND the tpacket3 block header.  The big
// difference is that tpacket3's block header implements the next() call to get
// the next packet within the block, while v1/v2 just always return false.

type header interface {
	// getStatus returns the TPacket status of the current header.
	getStatus() int
	// clearStatus clears the status of the current header, releasing its
	// underlying data back to the kernel for future use with new packets.
	// Using the header after calling clearStatus is an error.  clearStatus
	// should only be called after next() returns false.
	clearStatus()
	// getTime returns the timestamp for the current packet pointed to by
	// the header.
	getTime() time.Time
	// getData returns the packet data pointed to by the current header.
	getData(opts *options) []byte
	// getLength returns the total length of the packet.
	getLength() int
	// getIfaceIndex returns the index of the network interface
	// where the packet was seen. The index can later be translated to a name.
	getIfaceIndex() int
	// getVLAN returns the VLAN of a packet if it was provided out-of-band
	getVLAN() int
	// next moves this header to point to the next packet it contains,
	// returning true on success (in which case getTime and getData will
	// return values for the new packet) or false if there are no more
	// packets (in which case clearStatus should be called).
	next() bool
}

const tpacketAlignment = uint(unix.TPACKET_ALIGNMENT)

func tpAlign(x int) int {
	return int((uint(x) + tpacketAlignment - 1) &^ (tpacketAlignment - 1))
}

type v1header tpacketHdr
type v2header tpacket2Hdr

func makeSlice(start uintptr, length int) (data []byte) {
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	slice.Data = start
	slice.Len = length
	slice.Cap = length
	return
}

func insertVlanHeader(data []byte, vlanTCI int, opts *options) []byte {
	if vlanTCI == 0 || !opts.addVLANHeader {
		return data
	}
	eth := make([]byte, 0, len(data)+vlanHLen)
	eth = append(eth, data[0:ethALen*2]...)
	eth = append(eth, []byte{0x81, 0, byte((vlanTCI >> 8) & 0xff), byte(vlanTCI & 0xff)}...)
	return append(eth, data[ethALen*2:]...)
}

func (h *v1header) getVLAN() int {
	return -1
}
func (h *v1header) getStatus() int {
	return int(h.Status)
}
func (h *v1header) clearStatus() {
	h.Status = 0
}
func (h *v1header) getTime() time.Time {
	return time.Unix(int64(h.Sec), int64(h.Usec)*1000)
}
func (h *v1header) getData(opts *options) []byte {
	return makeSlice(uintptr(unsafe.Pointer(h))+uintptr(h.Mac), int(h.Snaplen))
}
func (h *v1header) getLength() int {
	return int(h.Len)
}
func (h *v1header) getIfaceIndex() int {
	ll := (*sockaddrLL)(unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(tpAlign(int(sizeofTpacketHdr)))))
	return int(ll.Ifindex)
}
func (h *v1header) next() bool {
	return false
}

func (h *v2header) getVLAN() int {
	return -1
}
func (h *v2header) getStatus() int {
	return int(h.Status)
}
func (h *v2header) clearStatus() {
	h.Status = 0
}
func (h *v2header) getTime() time.Time {
	return time.Unix(int64(h.Sec), int64(h.Nsec))
}
func (h *v2header) getData(opts *options) []byte {
	data := makeSlice(uintptr(unsafe.Pointer(h))+uintptr(h.Mac), int(h.Snaplen))
	return insertVlanHeader(data, int(h.Vlan_tci), opts)
}
func (h *v2header) getLength() int {
	return int(h.Len)
}
func (h *v2header) getIfaceIndex() int {
	ll := (*sockaddrLL)(unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(tpAlign(int(sizeofTpacket2Hdr)))))
	return int(ll.Ifindex)
}
func (h *v2header) next() bool {
	return false
}

type v3wrapper struct {
	block    *tpacketBlockDesc
	blockhdr *tpacketHdrV1
	packet   *tpacket3Hdr
	used     uint32
}

func initV3Wrapper(block unsafe.Pointer) (w v3wrapper) {
	w.block = (*tpacketBlockDesc)(block)
	w.blockhdr = (*tpacketHdrV1)(unsafe.Pointer(&w.block.Hdr[0]))
	w.packet = (*tpacket3Hdr)(unsafe.Pointer(uintptr(block) + uintptr(w.blockhdr.Offset_to_first_pkt)))
	return
}

func (w *v3wrapper) getVLAN() int {
	if w.packet.Status&unix.TP_STATUS_VLAN_VALID != 0 {
		return int(w.packet.Hv1.Vlan_tci & 0xfff)
	}
	return -1
}

func (w *v3wrapper) getStatus() int {
	return int(w.blockhdr.Block_status)
}
func (w *v3wrapper) clearStatus() {
	w.blockhdr.Block_status = 0
}
func (w *v3wrapper) getTime() time.Time {
	return time.Unix(int64(w.packet.Sec), int64(w.packet.Nsec))
}
func (w *v3wrapper) getData(opts *options) []byte {
	data := makeSlice(uintptr(unsafe.Pointer(w.packet))+uintptr(w.packet.Mac), int(w.packet.Snaplen))
	return insertVlanHeader(data, int(w.packet.Hv1.Vlan_tci), opts)
}
func (w *v3wrapper) getLength() int {
	return int(w.packet.Len)
}
func (w *v3wrapper) getIfaceIndex() int {
	ll := (*sockaddrLL)(unsafe.Pointer(uintptr(unsafe.Pointer(w.packet)) + uintptr(tpAlign(int(sizeofTpacket3Hdr)))))
	return int(ll.Ifindex)
}
func (w *v3wrapper) next() bool {
	w.used++
	if w.used >= w.blockhdr.Num_pkts {
		return false
	}

	next := uintptr(unsafe.Pointer(w.packet))
	if w.packet.Next_offset != 0 {
		next += uintptr(w.packet.Next_offset)
	} else {
		next += uintptr(tpAlign(int(w.packet.Snaplen) + int(w.packet.Mac)))
	}
	w.packet = (*tpacket3Hdr)(unsafe.Pointer(next))
	return true
}
