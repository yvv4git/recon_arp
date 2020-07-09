Recon network arp tool.
=======================

We send arp request message and listen to the channel(sniffing). When the answer comes, we analyze it. Then we add to the database technical information about the devices in the network.

How use:
--------
make

sudo ./scan.bin -iface enp2s0
