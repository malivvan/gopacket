// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcap

import "unsafe"

// uintptrToPointer converts a uintptr returned by purego.SyscallN into an
// unsafe.Pointer without tripping go vet's unsafeptr check (the value is a C
// address, not a Go pointer, so the usual GC-safety concerns do not apply).
func uintptrToPointer(p uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}

func byteSliceToString(bval []byte) string {
	for i := range bval {
		if bval[i] == 0 {
			return string(bval[:i])
		}
	}
	return string(bval[:])
}

// bytePtrToString returns a string copied from pointer to a null terminated byte array.
// WARNING: ONLY SAFE IF r POINTS TO C MEMORY!
func bytePtrToString(r uintptr) string {
	if r == 0 {
		return ""
	}
	bval := (*[1 << 30]byte)(uintptrToPointer(r))
	return byteSliceToString(bval[:])
}
