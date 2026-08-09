// Copyright 2024 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build linux
// +build linux

package afpacket

import "golang.org/x/sys/unix"

const (
	ethALen  = 6
	vlanHLen = 4
)

// Type aliases for tpacket types from golang.org/x/sys/unix.
// These replace the C struct types previously obtained via CGo.
type (
	tpacketHdr         = unix.TpacketHdr
	tpacket2Hdr        = unix.Tpacket2Hdr
	tpacket3Hdr        = unix.Tpacket3Hdr
	tpacketReq         = unix.TpacketReq
	tpacketReq3        = unix.TpacketReq3
	tpacketHdrVariant1 = unix.TpacketHdrVariant1
	tpacketBlockDesc   = unix.TpacketBlockDesc
	tpacketHdrV1       = unix.TpacketHdrV1
	sockaddrLL         = unix.RawSockaddrLinklayer
)

// tpacketStats and tpacketStatsV3 use unexported field names to avoid
// conflicts with the Packets()/Drops()/QueueFreezes() methods on SocketStats/SocketStatsV3.
type tpacketStats struct {
	packets uint32
	drops   uint32
}

type tpacketStatsV3 struct {
	packets    uint32
	drops      uint32
	freezeQCnt uint32
}

const (
	sizeofTpacketHdr  = unix.SizeofTpacketHdr
	sizeofTpacket2Hdr = unix.SizeofTpacket2Hdr
	sizeofTpacket3Hdr = unix.SizeofTpacket3Hdr
)
