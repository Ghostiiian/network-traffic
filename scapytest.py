import scapy
from scapy.all import *
from scapy.layers.tls import *
# from scapy_ssl_tls.ssl_tls import *

load_layer("tls")
Filename = "email2b.pcap"
packets = rdpcap(Filename)
filtered_packets = []

for packet in packets:
    if Ether in packet:
        packet = packet[Ether].payload  # 移除以太网头部
    if IP in packet:
        packet = packet[IP].payload  # 移除IPv4头部
    if TCP in packet:
        packet = packet[TCP].payload  # 移除TCP头部
    if UDP in packet:
        packet = packet[UDP].payload
    if packet.haslayer(TLS):
        packet = packet[TLS].payload  # 移除TLS头部

    filtered_packets.append(packet)

wrpcap('filtered_'+Filename, filtered_packets)
# for packet in packets:
print("finished")
#     data = packet.payload
#     print(data)
