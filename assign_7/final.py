from scapy.all import *
from datetime import datetime

# Part 1 - Student !!!
# Get the current time
timestamp = datetime.now()

packets = []
formatted_timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")

final_string = "Michail_Kratimenos-2018030104 " + formatted_timestamp

# Student Packet
packets.append( IP(src="192.168.0.0", dst="192.168.1.1") / TCP(dport=54321) / Raw(load = final_string) )

# Part 2 - Port scan !!!
# Get the current time
timestamp = datetime.now()

formatted_timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")

# List of ports for port scanning
# source: https://sumofbytes.com/blog/cheatsheet-default-ports-of-popular-databases-and-network-internet-protocols
ports = [80, 443, 22, 23, 21, 53, 554, 3306, 3389, 1883]  # HTTP, HTTPS, SSH, etc.
name_am = "Michail_Kratimenos-2018030104 "
# Generate port scan packets
for port in ports:
    # While most services use TCP, DNS often uses UDP for smaller queries due to its efficiency, 
    # but here the query is too large to fit into a UDP, so TCP is used.
    pkt = IP(src="192.168.0.1", dst="192.168.1.2") / TCP(dport=port) / Raw(load=name_am + formatted_timestamp)
    packets.append(pkt)

# Part 3 - Base64 malicious payload !!!
student_id = "2018030104"
encoded_payload = base64.b64encode(student_id.encode()).decode()

for _ in range(5):
    pkt = IP(src="192.168.0.2", dst="192.168.1.3") / TCP(dport=8080) / Raw(load=encoded_payload)
    packets.append(pkt)
    
# Part 4 - DNS Query Packet !!!
# to get VM's IP, I executed in the terminal: cat /etc/resolv.conf and got: nameserver 127.0.0.53
packets.append( IP(src="192.168.0.3", dst="127.0.0.53") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="malicious.example.com")) )

# Part 5 - ICMP Packet !!!
packets.append( IP(src="192.168.0.4", dst="192.168.1.4") / ICMP() / Raw(load="PingTest-2024") )

wrpcap("final.pcap", packets)

