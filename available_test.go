// Copyright 2024 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package gopacket

import (
	"os"
	"strings"
	"testing"
)

func TestPuregoPlatformSupported(t *testing.T) {
	cases := []struct {
		goos, goarch string
		want         bool
	}{
		{"linux", "amd64", true},
		{"linux", "arm64", true},
		{"linux", "386", true},
		{"linux", "ppc64le", true},
		{"windows", "amd64", true},
		{"windows", "386", true},
		{"darwin", "amd64", true},
		{"darwin", "arm64", true},
		{"freebsd", "amd64", true},
		{"netbsd", "amd64", true},
		// Unsupported platforms / architectures.
		{"openbsd", "amd64", false},
		{"dragonfly", "amd64", false},
		{"aix", "ppc64", false},
		{"solaris", "amd64", false},
		{"plan9", "amd64", false},
		{"linux", "wasm", false},
		{"linux", "mips64", false},
	}
	for _, c := range cases {
		if got := puregoPlatformSupported(c.goos, c.goarch); got != c.want {
			t.Errorf("puregoPlatformSupported(%q, %q) = %v, want %v", c.goos, c.goarch, got, c.want)
		}
	}
}

// TestAvailableNoLibraryLoading verifies that calling Available() never pulls a
// capture library (libpcap/wpcap) into the process.
func TestAvailableNoLibraryLoading(t *testing.T) {
	before := mappedLibraries(t)
	_ = Available()
	after := mappedLibraries(t)
	for _, lib := range []string{"libpcap", "wpcap"} {
		if strings.Contains(after, lib) && !strings.Contains(before, lib) {
			t.Errorf("Available() loaded %q into the process", lib)
		}
	}
}

func mappedLibraries(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Skipf("cannot read /proc/self/maps: %v", err)
	}
	return string(data)
}
