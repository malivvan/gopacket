// Copyright 2024 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pfring

import "testing"

// TestPkthdrOffsetsForVersion verifies that the if_index field offset within
// the packed pfring_extended_pkthdr is selected from the PF_RING version.
// PF_RING 7.8.0 inserted port_id/device_id between rx_direction and if_index,
// moving if_index from byte 13 to byte 16 of the extended header.
func TestPkthdrOffsetsForVersion(t *testing.T) {
	cases := []struct {
		version uint32
		want    int
	}{
		{0x000000, offsetExtHdr + ifIndexOffsetLegacy}, // ancient
		{0x060400, offsetExtHdr + ifIndexOffsetLegacy}, // 6.4.0
		{0x070600, offsetExtHdr + ifIndexOffsetLegacy}, // 7.6.0
		{0x070800, offsetExtHdr + ifIndexOffsetModern}, // 7.8.0 (cutoff)
		{0x080000, offsetExtHdr + ifIndexOffsetModern}, // 8.0.0
		{0x090300, offsetExtHdr + ifIndexOffsetModern}, // dev/9.3.0
	}
	for _, c := range cases {
		setPkthdrOffsetsForVersion(c.version)
		if offsetIfIndex != c.want {
			t.Errorf("version %#x: offsetIfIndex = %d, want %d", c.version, offsetIfIndex, c.want)
		}
	}
	// Restore the default in case other tests depend on it.
	setPkthdrOffsetsForVersion(0)
}
