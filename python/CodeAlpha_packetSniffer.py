from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = None
        payload = None

        if TCP in packet:
            protocol = "TCP"
            payload = bytes(packet[TCP].payload)
        elif UDP in packet:
            protocol = "UDP"
            payload = bytes(packet[UDP].payload)
        elif ICMP in packet:
            protocol = "ICMP"
            payload = bytes(packet[ICMP].payload)
        else:
            protocol = str(ip_layer.proto)  

        print(f"Source IP: {src_ip} -> Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        if payload:
           
            print(f"Payload (first 50 bytes): {payload[:50]}")
        print("-" * 50)
  
def main():
    print("Starting packet capture. Press Ctrl+C to stop.")
    
    sniff(prn=packet_callback, store=False)

if __name__ == "_main_":
    main()