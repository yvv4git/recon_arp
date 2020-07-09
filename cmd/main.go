package main

import (
	"flag"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/yvv4git/goexamples/net/arp/send_arp/arp"
	"github.com/yvv4git/goexamples/net/ipv4_address"
)

// Use:
// go run main.go -iface wlp2s0
// or
// go build
// ./send_subnet -iface wlp2s0
//
// sudo tshark -i wlp2s0 -f 'arp'
func main() {
	ifaceName := flag.String("iface", "wlp2s0", "Name of network interface")
	flag.Parse()

	log.Println("Interface name: ", *ifaceName)

	var ipV4Net *net.IPNet
	var ipv4Addresses []net.IP

	// init arp package
	arpSender := arp.NewArpSender()
	arpSender.SetIface(*ifaceName)
	ipV4Net = arpSender.GetIpV4Net()
	log.Println("IPv4 net:", ipV4Net)

	// calculate ipv4 addresses list
	ipv4Addresses, err := ipv4_address.GetIPv4AddressesFromNet(ipV4Net)
	if nil != err {
		panic("IP address is not ipv4 address")
	}

	// open device
	handle, err := pcap.OpenLive(*ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// sniff
	go readARP(handle, arpSender.GetIface())

	// send arp request for every ip address
	for _, ipv4Addres := range ipv4Addresses {
		arpSender.SetDstIpV4(ipv4Addres)

		arpPackage := arpSender.GenerateArpPackage()

		// send arp package
		if err := handle.WritePacketData(arpPackage); err != nil {
			panic(err)
		}
	}
}

func readARP(handle *pcap.Handle, iface *net.Interface) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		select {
		case packet, status := <-in:
			if !status {
				// канал закрыт, выходим из функции
				return
			}

			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}

			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				// это скорее всего мой пакет, ибо мне нужны только ответы
				continue
			}

			log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}
