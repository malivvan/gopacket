#!/bin/bash

set -ev

go test github.com/malivvan/gopacket
go test github.com/malivvan/gopacket/layers
go test github.com/malivvan/gopacket/tcpassembly
go test github.com/malivvan/gopacket/reassembly
go test github.com/malivvan/gopacket/pcapgo
go test github.com/malivvan/gopacket/pcap
sudo $(which go) test github.com/malivvan/gopacket/routing
