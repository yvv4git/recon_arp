# Recon network arp tool.

We send arp request message and listen to the channel(sniffing). When the answer comes, we analyze it. Then we add to the database technical information about the devices in the network.

## Install pcap
apt-get install libpcap-dev

## USE
```
make
sudo ./scan.bin -iface enp2s0
```

![screenshot of sample](https://github.com/yvv4git/recon_arp/blob/master/about.png)
