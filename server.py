from scapy.all import *

mac_dst = "00:00:00:00:00:02"

os.system("tcpdump -t udp -w ./server.pcap&>/dev/null")

while True:
    receive = sniff(filter="udp", count=1)
    if hasattr(receive[0], 'load') and str(receive[0].load).startswith("SDN_SPY_"):
        if str(receive[0].load) == "SDN_SPY_exit":
            break
        pkt = receive[0]

        src_mac = pkt[Ether].src
        src_ip = pkt[IP].src
        src_port = pkt[UDP].sport

        pkt[Ether].src = pkt[Ether].dst
        pkt[IP].src = pkt[IP].dst
        pkt[UDP].sport = pkt[UDP].dport

        pkt[Ether].dst = src_mac
        pkt[IP].dst = src_ip
        pkt[UDP].dport = src_port

        sendp(pkt)

os.system("killall tcpdump")
print "finished"
