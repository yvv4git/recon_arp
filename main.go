/*
Use:
make build
./send_subnet -iface wlp2s0
./scan.bin -iface enp2s0

### May check
sudo tshark -i wlp2s0 -f 'arp'
*/
package main

import (
	"flag"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/yvv4git/netarp"
	"github.com/yvv4git/netipv4"
)

func main() {
	var srcIP net.IP
	var netAddress *net.IPNet
	var ipv4AddressesList []net.IP

	ifaceName := flag.String("iface", "wlp2s0", "Name of network interface")
	flag.Parse()

	log.Println("Interface name: ", *ifaceName)

	// init iface
	iface, err := net.InterfaceByName(*ifaceName)
	if nil != err {
		panic("Don't find interface.")
	}

	// calculate ipv4 list and options
	srcIP = netipv4.GetIpv4FromIface(iface)
	netAddress = netipv4.GetNetworkAddressFromIface(iface)
	ipv4AddressesList, err = netipv4.GetIPv4AddressesFromNet(netAddress)
	if nil != err {
		panic("IP address is not ipv4 address")
	}

	// init and setup arp package sender
	arpGenerator := netarp.NewArpGenerator()
	arpGenerator.SetIface(iface)
	arpGenerator.SetSrcIp(srcIP)

	// open device for sniffing channel
	handle, err := pcap.OpenLive(*ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// sniffing and analyse
	go readPackages(handle, iface)

	// send arp request for every ip address in subnet
	for _, ipv4Addres := range ipv4AddressesList {
		arpGenerator.SetDstIp(ipv4Addres)
		arpPackage := arpGenerator.GenerateArpPackage()

		// send arp package
		if err := handle.WritePacketData(arpPackage); err != nil {
			panic(err)
		}
	}
}

// Read packages from channel
func readPackages(handle *pcap.Handle, iface *net.Interface) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		select {
		case packet, status := <-in:
			if !status {
				// sniff channel is closed
				return
			}

			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}

			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				// we want only arp replay packets
				continue
			}

			log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}
