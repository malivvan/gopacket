# GoPacket

This library provides packet decoding capabilities for Go.

This repository is a fork of [google/gopacket](https://github.com/google/gopacket)
(via [Mzack9999/gopacket](https://github.com/Mzack9999/gopacket)) with one major
change: **all CGO usage has been replaced with
[purego](https://github.com/ebitengine/purego)** — libpcap / libpfring are loaded
at runtime with `dlopen` and called through `purego.SyscallN`. No C compiler is
needed to build or cross-compile any package in this module.

## Why purego

The upstream project uses CGO (`import "C"`) to talk to `libpcap` (pcap package)
and `libpfring` (pfring package). CGO has several downsides:

- requires a C toolchain to build and cross-compile,
- links against a *specific* libpcap at build time,
- makes static binaries and tiny container images harder to produce.

With purego, the shared libraries are discovered at runtime (`libpcap.so.1`,
`libpcap.dylib`, `libpfring.so.1`, …), so the same binary runs against whatever
libpcap/libpfring version is installed on the target machine, and the module
builds with `CGO_ENABLED=0` as well.

## Requirements

- Go **1.26.5** or newer (`go.mod` declares `go 1.26.5`).
- `github.com/ebitengine/purego v0.10.2` (pulled in automatically).
- The platform's C library (`libc`) for `malloc`/`free` interop with
  `pcap_freecode` (glibc, musl, macOS libSystem, FreeBSD/NetBSD/OpenBSD libc
  are all probed by name).

## Installation

```bash
go get github.com/malivvan/gopacket
```

No CGO, no libpcap headers, no `CGO_ENABLED=1` — `go build` just works, including
cross-compilation (`GOOS=windows GOARCH=amd64 go build ./...`, etc.).

At runtime the `pcap` package needs libpcap installed on the target (e.g.
`libpcap0.8` on Debian/Ubuntu, Npcap on Windows), and the `pfring` package needs
the PF_RING userland library. If a library is missing, the package reports a
clear load error instead of failing to build.

## Supported platforms

- **Linux** (amd64, 386, arm, arm64, …) — pcap, afpacket, pfring, rawsend.
- **Windows** (amd64, 386) — pcap via wpcap.dll/Npcap (loaded with
  `golang.org/x/sys/windows`; `Dlopen`/`Dlsym` are Unix-only in purego).
- **macOS** — pcap via libpcap.dylib / libSystem.
- **BSD family** (FreeBSD, NetBSD, OpenBSD, DragonFly) — pcap; bsdbpf.

## Packages

| Package      | Description                                                                 |
|--------------|-----------------------------------------------------------------------------|
| `pcap`       | Live/offline capture and BPF filtering through dynamically loaded libpcap.  |
| `pfring`     | PF_RING capture through dynamically loaded libpfring.                       |
| `afpacket`   | Linux AF_PACKET / TPACKET capture (v1/v2/v3) via plain syscalls.            |
| `rawsend`    | High-performance raw IPv4 sending with optional `sendmmsg` batching.        |
| `pcapgo`     | Read/write pcap & pcapng files (pure Go).                                   |
| `bsdbpf`     | BSD BPF device capture (pure Go).                                           |
| `layers`, `reassembly`, `tcpassembly`, `ip4defrag`, `defrag`, `macs`, `bytediff`, … | Same as upstream.                |

## Usage

Decode packets from a pcap file:

```go
package main

import (
	"fmt"

	"github.com/malivvan/gopacket"
	"github.com/malivvan/gopacket/layers"
	"github.com/malivvan/gopacket/pcap"
)

func main() {
	handle, err := pcap.OpenOffline("test.pcap")
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("TCP %s -> %s\n", tcp.SrcPort, tcp.DstPort)
		}
	}
}
```

Live capture with a BPF filter:

```go
handle, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
if err != nil {
	panic(err)
}
defer handle.Close()
if err := handle.SetBPFFilter("tcp port 80"); err != nil {
	panic(err)
}
```

Compile and run a BPF filter without any live handle:

```go
bpf, err := pcap.NewBPF(layers.LinkTypeEthernet, 65535, "icmp")
if err != nil {
	panic(err)
}
if bpf.Matches(ci, packetData) {
	// packetData matches "icmp"
}
```

## Key differences from upstream google/gopacket

- **No CGO anywhere.** `pcap` and `pfring` load their C libraries at runtime via
  purego; `afpacket`/`bsdbpf`/`rawsend` use plain syscalls via
  `golang.org/x/sys`.
- **C struct definitions are Go-native** (see `pcap/defs_unix.go`,
  `pfring/defs_linux.go`, `afpacket/defs_linux.go`) with layout tests
  (`pcap/defs_unix_test.go`, `pfring/defs_linux_test.go`).
- **BPF instruction filters** (`SetBPFInstructionFilter`,
  `NewBPFInstructionFilter`) allocate the instruction buffer with the platform
  C allocator (`malloc`/`calloc`) so `pcap_freecode` can safely release it.
- **PF_RING metadata parsing** is layout-aware: the packed `pfring_pkthdr`
  is parsed at byte offsets that are chosen from the loaded PF_RING version
  (`pfring_version_noring`); `if_index` moved from offset 13 to 16 in
  PF_RING ≥ 7.8.0.
- **`rawsend`** — new package for low-overhead raw packet sending, with a
  `sendmmsg`-based `Batch` on Linux (loaded via purego).
- Module path is `github.com/malivvan/gopacket`.

## Testing

```bash
go build ./...
go vet ./...
go test ./...
```

Notes:

- `pcap` tests need libpcap installed and use the bundled `*.pcap` fixtures;
  `TestBPFInstruction` compares compiled BPF programs semantically, because
  libpcap ≥ 1.10.2 emits a different but equivalent instruction order (see
  upstream issue [google/gopacket#1088](https://github.com/google/gopacket/issues/1088)).
- `routing.TestRouting` creates veth pairs and network namespaces and therefore
  requires root — it is skipped automatically when running unprivileged.
- `afpacket` / `rawsend` tests that touch real interfaces need root /
  `CAP_NET_RAW` and are skipped otherwise.

## Attribution & license

Originally forked from the gopcap project written by Andreas
Krennmair <ak@synflood.at> (<http://github.com/akrennmair/gopcap>), with the
bulk of the code coming from [google/gopacket](https://github.com/google/gopacket)
and the purego port based on
[Mzack9999/gopacket](https://github.com/Mzack9999/gopacket).

This module is distributed under the same BSD-3-Clause license as upstream
(see `LICENSE`). The purego dependency is licensed under Apache-2.0.
