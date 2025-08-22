# CodeAlpha-Basic-network-sniffer
# 🛰️ Basic Network Sniffer

## 📌 Overview
This project is a **basic network sniffer** built in Python as part of an assignment.  
It uses the **Scapy** library to capture live network traffic and display useful information such as:

- ✅ Source and Destination IP addresses  
- ✅ Protocols (TCP, UDP, ICMP, etc.)  
- ✅ Payload data (first 50 bytes)  

This helps in understanding how **data flows through the network** and the structure of packets.

---

## ⚙️ Requirements
- Python 3.13+
- [Scapy](https://scapy.net/)
- [Npcap](https://npcap.com/) (Windows only, required for packet capture)

Install Scapy using:
```bash
pip install scapy
