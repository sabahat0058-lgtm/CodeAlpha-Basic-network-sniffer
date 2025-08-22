from scapy.all import sniff

print("Sniffing 5 packets...")
packets = sniff(count=5)
packets.summary()
