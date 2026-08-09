// Copyright 2024 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build linux
// +build linux

package pfring

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// PF_RING flag constants from <linux/pf_ring.h>.
const (
	flagReentrant       = 1 << 0
	flagLongHeader      = 1 << 1
	flagPromisc         = 1 << 2
	flagDNASymmetricRSS = 1 << 6
	flagTimestamp       = 1 << 4
	flagHWTimestamp     = 1 << 5
)

// cluster_type enum values from <linux/pf_ring.h>.
const (
	clusterPerFlow         = 0
	clusterRoundRobin      = 1
	clusterPerFlow2Tuple   = 2
	clusterPerFlow4Tuple   = 3
	clusterPerFlow5Tuple   = 4
	clusterPerFlowTCP5Tuple = 5
)

// packet_direction enum values from <linux/pf_ring.h>.
const (
	rxAndTxDirection = 0
	rxOnlyDirection  = 1
	txOnlyDirection  = 2
)

// socket_mode enum values from <linux/pf_ring.h>.
const (
	sendAndRecvMode = 0
	recvOnlyMode    = 1
	sendOnlyMode    = 2
)

// pfringStats mirrors C's pfring_stat { u_int64_t recv, drop; }.
type pfringStats struct {
	Recv uint64
	Drop uint64
}

// Offsets within the packed pfring_pkthdr struct for parsing after pfring_recv.
//
// pfring_pkthdr layout (packed):
//   struct timeval ts;                    // timevalSize bytes
//   u_int32_t     caplen;                // 4 bytes
//   u_int32_t     len;                   // 4 bytes
//   struct pfring_extended_pkthdr {      // begins at timevalSize + 8
//     u_int64_t   timestamp_ns;          //   8 bytes (offset 0)
//     u_int32_t   flags;                 //   4 bytes (offset 8)
//     u_int8_t    rx_direction;          //   1 byte  (offset 12)
//     u_int8_t    port_id;               //   1 byte  (offset 13)  PF_RING >= 7.8.0
//     u_int16_t   device_id;             //   2 bytes (offset 14)  PF_RING >= 7.8.0
//     int32_t     if_index;              //   4 bytes (offset 13 or 16)
//     ...
//   } extended_hdr;
//
// PF_RING 7.8.0 inserted port_id and device_id between rx_direction and
// if_index, moving if_index from byte 13 to byte 16 of the extended header.
// The old cgo code let the C compiler compute this offset; with purego the
// offset is chosen at load time from the library version (see
// setPkthdrOffsetsForVersion).
var (
	timevalSize   = int(unsafe.Sizeof(unix.Timeval{}))
	offsetCaplen  = timevalSize
	offsetLen     = timevalSize + 4
	offsetExtHdr  = timevalSize + 8
	offsetTsNs    = offsetExtHdr + 0
	offsetIfIndex = offsetExtHdr + ifIndexOffsetLegacy
)

const (
	// ifIndexOffsetLegacy is the offset of if_index within the extended
	// header for PF_RING < 7.8.0 (no port_id/device_id fields).
	ifIndexOffsetLegacy = 13
	// ifIndexOffsetModern is the offset of if_index within the extended
	// header for PF_RING >= 7.8.0.
	ifIndexOffsetModern = 16
)

// setPkthdrOffsetsForVersion adjusts the pfring_pkthdr field offsets for the
// loaded PF_RING version. version is the value returned by
// pfring_version_noring() (0xMMmmpp encoding).
func setPkthdrOffsetsForVersion(version uint32) {
	if version >= 0x070800 {
		offsetIfIndex = offsetExtHdr + ifIndexOffsetModern
	} else {
		offsetIfIndex = offsetExtHdr + ifIndexOffsetLegacy
	}
}

// pfringPkthdrBufSize is a generous upper bound for the pfring_pkthdr struct.
const pfringPkthdrBufSize = 1024
