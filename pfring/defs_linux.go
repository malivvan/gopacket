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
//     int32_t     if_index;              //   4 bytes (offset 13)
//     ...
//   } extended_hdr;
var (
	timevalSize     = int(unsafe.Sizeof(unix.Timeval{}))
	offsetCaplen    = timevalSize
	offsetLen       = timevalSize + 4
	offsetExtHdr    = timevalSize + 8
	offsetTsNs      = offsetExtHdr + 0
	offsetIfIndex   = offsetExtHdr + 13
)

// pfringPkthdrBufSize is a generous upper bound for the pfring_pkthdr struct.
const pfringPkthdrBufSize = 1024
