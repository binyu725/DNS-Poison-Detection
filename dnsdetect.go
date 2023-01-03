package main

import  (
	"fmt"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"log"
	"strings"
	"reflect"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err!= nil {
		log.Fatal(err)
	}
	
	device := flag.String("i", devices[0].Name, "device")
	tracefile := flag.String("r", "", "tracefile")
	
	flag.Parse()

	expressionAry := flag.Args()
	expression := strings.Join(expressionAry, " ")
	if expression != "" {
		expression += " and udp port 53"
	} else {
		expression += "udp port 53"
	}

	detect(*device, *tracefile, expression)
}

func detect(device, tracefile, expression string) {
	var handle *pcap.Handle
	var err error

	if tracefile != "" {
		// read packets from file
		handle, err = pcap.OpenOffline(tracefile)
	} else if device != "" {
		// capture from the network device
		handle, err = pcap.OpenLive(device, 1024, true, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// use bpf filter to specifies the packets by expression entered by user
	if err := handle.SetBPFFilter(expression); err != nil {
		log.Fatal(err)
	}
	
	packetList := make([]gopacket.Packet, 0)
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
		ethLayer := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		udpLayer := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		
		if dnsLayer == nil || ethLayer == nil || ipv4Layer == nil || udpLayer == nil {
			continue
		}
		
		if len(packetList) > 0 {
			for _, p := range packetList {
				dns := p.Layer(layers.LayerTypeDNS).(*layers.DNS)
				eth := p.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
				ipv4 := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				udp := p.Layer(layers.LayerTypeUDP).(*layers.UDP)
				
				if (dnsLayer.ID == dns.ID &&
				dnsLayer.QR == true &&
				dns.QR == true && 
				reflect.DeepEqual(dnsLayer.Questions[0].Name, dns.Questions[0].Name) && 
				reflect.DeepEqual(ethLayer.SrcMAC, eth.SrcMAC) && 
				reflect.DeepEqual(ethLayer.DstMAC, eth.DstMAC) && 
				reflect.DeepEqual(ipv4Layer.SrcIP, ipv4.SrcIP) && 
				reflect.DeepEqual(ipv4Layer.DstIP, ipv4.DstIP) && 
				reflect.DeepEqual(udpLayer.SrcPort, udp.SrcPort) && 
				reflect.DeepEqual(udpLayer.DstPort, udp.DstPort)) {
					var index1, index2 int
					for i, a := range dns.Answers {
						if a.Type == layers.DNSTypeA && a.Class == layers.DNSClassIN {
							index1 = i
							break
						}
					}
					for i, a := range dnsLayer.Answers {
						if a.Type == layers.DNSTypeA && a.Class == layers.DNSClassIN {
							index2 = i
							break
						}
					}
					if !reflect.DeepEqual(dns.Answers[index1].IP, dnsLayer.Answers[index2].IP) && !reflect.DeepEqual(dns.Answers[index1].Data, dnsLayer.Answers[index2].Data) {
						fmt.Println(packet.Metadata().CaptureInfo.Timestamp, "DNS poisoning attempt")
						fmt.Println("TXID", dnsLayer.ID, "Request", string(dnsLayer.Questions[0].Name))
						fmt.Print("Answer1 [", dns.Answers[index1].IP, "]\n")
						fmt.Print("Answer2 [", dnsLayer.Answers[index2].IP, "]\n\n")
					}
				}
			}
		}
		
		packetList = append(packetList, packet)
	}
}
