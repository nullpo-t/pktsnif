package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func isDNSPacket(p gopacket.Packet) bool {
	dnsLayers := []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeIPv4, layers.LayerTypeUDP, layers.LayerTypeDNS}
	for i, l := range p.Layers() {
		if l.LayerType() != dnsLayers[i] {
			return false
		}
	}
	return true
}

func isDNSResponse(p gopacket.Packet) bool {
	return p.Layer(layers.LayerTypeDNS).(*layers.DNS).QR
}

func getDNSRespQ(p gopacket.Packet) (s []string) {
	questions := p.Layer(layers.LayerTypeDNS).(*layers.DNS).Questions
	for _, q := range questions {
		s = append(s, string(q.Name))
	}
	return
}

func getDNSRespA(p gopacket.Packet) (s []string) {
	answers := p.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers
	for _, a := range answers {
		if a.Type == layers.DNSTypeA {
			s = append(s, a.IP.String())
		}
	}
	return
}

func getL3DstIP(p gopacket.Packet) net.IP {
	return p.Layer(layers.LayerTypeIPv4).(*layers.IPv4).DstIP
}

func getL3SrcIP(p gopacket.Packet) net.IP {
	return p.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP
}

type DNSResponse struct {
	PacketNumber int
	TimeStamp    time.Time
	L3SrcIP      net.IP
	L3DstIP      net.IP
	Query        []string
	Answer       []string
}

func GetDNSResponses(handle *pcap.Handle) []*DNSResponse {
	defer handle.Close()
	var ret []*DNSResponse
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	c := 0
	for packet := range src.Packets() {
		c++
		if isDNSPacket(packet) && isDNSResponse(packet) {
			ret = append(ret, &DNSResponse{
				PacketNumber: c,
				TimeStamp:    packet.Metadata().Timestamp,
				L3SrcIP:      getL3SrcIP(packet),
				L3DstIP:      getL3DstIP(packet),
				Query:        getDNSRespQ(packet),
				Answer:       getDNSRespA(packet),
			})
		}
	}
	return ret
}

func FilterDNSResponses(packets []*DNSResponse, filter []string) []*DNSResponse {
	var ret []*DNSResponse
	for _, p := range packets {
		for _, f := range filter {
			for _, pa := range p.Answer {
				if pa == f {
					ret = append(ret, p)
				}
			}
		}
	}
	return ret
}

func main() {
	usage := `Usage:
  %s PCAP_FILE IP_ADDRESS...
Example:
  %s abc.pcap 10.0.0.1 10.0.0.2
`
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, usage, os.Args[0], os.Args[0])
		os.Exit(1)
	}

	filter := os.Args[2:]
	handle, err := pcap.OpenOffline(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	resp := GetDNSResponses(handle)
	filtered := FilterDNSResponses(resp, filter)
	for _, p := range filtered {
		fmt.Println(p)
	}
}
