// Copyright 2024 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package gopacket

import (
	"os"
	"runtime"
)

// Available reports whether this build can use the capture functionality of the
// gopacket sub-packages (pcap, pfring, ...).
//
// It returns true only if both of the following hold:
//
//   - the current platform (GOOS/GOARCH) is supported by the purego dynamic
//     loading layer used by this fork, and
//   - the shared libraries required for capture (libpcap / wpcap.dll) are
//     present on the system.
//
// Available is a best-effort, side-effect free probe: it never calls dlopen,
// LoadLibrary or any other library loading mechanism, and it does not resolve
// symbols. It checks well-known filesystem locations, so it may report false
// for unusual installations (e.g. libpcap reachable only through
// LD_LIBRARY_PATH or a custom prefix) even though loading would succeed.
// Conversely, a file existing at a probed path does not guarantee that
// loading will succeed. Use it as a cheap gate before attempting capture;
// actual loading errors are reported by the pcap/pfring packages themselves.
func Available() bool {
	if !isPuregoPlatformSupported() {
		return false
	}
	return hasCaptureLibraries()
}

// isPuregoPlatformSupported reports whether purego's SyscallN/Dlopen layer is
// available on this GOOS/GOARCH (mirrors purego's build-tag matrix).
func isPuregoPlatformSupported() bool {
	return puregoPlatformSupported(runtime.GOOS, runtime.GOARCH)
}

func puregoPlatformSupported(goos, goarch string) bool {
	switch goos {
	case "linux", "darwin", "freebsd", "netbsd", "windows":
	default:
		return false
	}
	switch goarch {
	case "386", "amd64", "arm", "arm64", "loong64", "ppc64le", "riscv64", "s390x":
	default:
		return false
	}
	return true
}

// hasCaptureLibraries reports whether the libpcap shared library (or wpcap.dll
// on Windows) can be found in a well-known location. It only inspects the
// filesystem and never loads any library into the process.
func hasCaptureLibraries() bool {
	var paths []string
	switch runtime.GOOS {
	case "windows":
		paths = []string{
			`C:\Windows\System32\Npcap\wpcap.dll`,
			`C:\Windows\System32\wpcap.dll`,
			`C:\Windows\SysWOW64\Npcap\wpcap.dll`,
		}
	case "darwin":
		paths = []string{
			"/usr/lib/libpcap.dylib",
			"/usr/local/lib/libpcap.dylib",
			"/opt/homebrew/lib/libpcap.dylib",
		}
	case "freebsd", "netbsd":
		paths = []string{
			"/usr/lib/libpcap.so",
			"/usr/local/lib/libpcap.so",
		}
	default: // linux
		paths = []string{
			// Debian/Ubuntu multiarch (note: the real file is usually only
			// reachable through the SONAME, e.g. libpcap.so.0.8).
			"/usr/lib/x86_64-linux-gnu/libpcap.so.1",
			"/usr/lib/x86_64-linux-gnu/libpcap.so.0.8",
			"/usr/lib/x86_64-linux-gnu/libpcap.so",
			"/usr/lib/aarch64-linux-gnu/libpcap.so.1",
			"/usr/lib/aarch64-linux-gnu/libpcap.so.0.8",
			"/usr/lib/aarch64-linux-gnu/libpcap.so",
			"/usr/lib/i386-linux-gnu/libpcap.so.1",
			"/usr/lib/i386-linux-gnu/libpcap.so.0.8",
			"/usr/lib/i386-linux-gnu/libpcap.so",
			"/lib/x86_64-linux-gnu/libpcap.so.1",
			"/lib/x86_64-linux-gnu/libpcap.so.0.8",
			"/lib/aarch64-linux-gnu/libpcap.so.1",
			"/lib/aarch64-linux-gnu/libpcap.so.0.8",
			// RHEL/Fedora/CentOS
			"/usr/lib64/libpcap.so.1",
			"/usr/lib64/libpcap.so.0.8",
			"/usr/lib64/libpcap.so",
			// Generic
			"/usr/lib/libpcap.so.1",
			"/usr/lib/libpcap.so.0.8",
			"/usr/lib/libpcap.so",
			"/usr/local/lib/libpcap.so.1",
			"/usr/local/lib/libpcap.so.0.8",
			"/usr/local/lib/libpcap.so",
		}
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}
