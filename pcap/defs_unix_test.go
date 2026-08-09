// Copyright 2024 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build !windows
// +build !windows

package pcap

import (
	"testing"
	"unsafe"
)

func TestPcapPkthdrLayout(t *testing.T) {
	var h pcapPkthdr
	tsSize := unsafe.Sizeof(h.Ts)

	if off := unsafe.Offsetof(h.Caplen); off != tsSize {
		t.Errorf("pcapPkthdr.Caplen offset = %d, want %d (sizeof Timeval)", off, tsSize)
	}
	if off := unsafe.Offsetof(h.Len); off != tsSize+4 {
		t.Errorf("pcapPkthdr.Len offset = %d, want %d", off, tsSize+4)
	}
	totalExpected := tsSize + 8
	if sz := unsafe.Sizeof(h); sz != totalExpected {
		t.Errorf("sizeof(pcapPkthdr) = %d, want %d", sz, totalExpected)
	}
}

func TestPcapBpfInstructionSize(t *testing.T) {
	if sz := unsafe.Sizeof(pcapBpfInstruction{}); sz != 8 {
		t.Errorf("sizeof(pcapBpfInstruction) = %d, want 8", sz)
	}
}

func TestPcapBpfProgramLayout(t *testing.T) {
	var p pcapBpfProgram
	ptrSize := unsafe.Sizeof(uintptr(0))

	expectedSize := uintptr(4)
	if ptrSize == 8 {
		expectedSize = 16 // 4 byte uint32 + 4 byte padding + 8 byte pointer
	} else {
		expectedSize = 8 // 4 byte uint32 + 4 byte pointer
	}
	if sz := unsafe.Sizeof(p); sz != expectedSize {
		t.Errorf("sizeof(pcapBpfProgram) = %d, want %d (ptrSize=%d)", sz, expectedSize, ptrSize)
	}
}

func TestPcapStatsSize(t *testing.T) {
	if sz := unsafe.Sizeof(pcapStats{}); sz != 12 {
		t.Errorf("sizeof(pcapStats) = %d, want 12", sz)
	}
}
