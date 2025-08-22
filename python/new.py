from scapy.all import get_working_ifaces

print("Working interfaces:")
for iface in get_working_ifaces():
    print(iface.name, iface.description)
