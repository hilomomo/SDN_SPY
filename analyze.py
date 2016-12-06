from scapy.all import *

client_pacp = rdpcap("client.pcap")
server_pacp = rdpcap("server.pcap")

client_time = []
server_time = []
title_dict = ["DST_PORT", "SRC_PORT", "TOS", "SRC_IP", "DST_IP", "SRC_MAC"]

for i in range(0, len(client_pacp)):
    packet = client_pacp[i]
    if hasattr(packet, 'load') and str(packet.load).startswith("SDN_SPY_D"):
        client_time.append(packet.time)

for i in range(0, len(server_pacp)):
    packet = server_pacp[i]
    if hasattr(packet, 'load') and str(packet.load).startswith("SDN_SPY_D"):
        server_time.append(packet.time)

print "%10s%15s%15s%15s%15s" % ("FIELD", "P1_SEND", "P1_RECV", "P2_SEND", "P2_RECV")
if len(client_time) == len(server_time) == 24:
    for i in range(0, len(client_time), 4):
        print "%10s%15.2f%15.2f%15.2f%15.2f" % (
            (title_dict[i / 4]), (server_time[i] - client_time[i]) * 100000000,
            (client_time[i + 1] - server_time[i + 1]) * 100000000,
            (server_time[i + 2] - client_time[i + 2]) * 100000000,
            (client_time[i + 3] - server_time[i + 3]) * 100000000)
else:
    print "data mismatch"
