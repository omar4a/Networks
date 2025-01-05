import scapy.all as scapy
import psutil
import ipaddress
import socket
import random

def get_network_info():
    interfaces = psutil.net_if_addrs()
    ip_address = None
    netmask = None
    network_interface = None

    for interface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("169.254"):
                ip_address = addr.address
                netmask = addr.netmask
                network_interface = interface
                break
        if ip_address and netmask:
            break

    if ip_address is None or netmask is None:
        raise ValueError("Unable to determine network address or netmask")

    network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    return network, ip_address, netmask, network_interface

def send_dhcp_discover(network_interface, transaction_id):
    dhcp_discover = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / \
                    scapy.IP(src="0.0.0.0", dst="255.255.255.255") / \
                    scapy.UDP(dport=67, sport=68) / \
                    scapy.BOOTP(chaddr=scapy.get_if_hwaddr(network_interface), xid=transaction_id) / \
                    scapy.DHCP(options=[("message-type", "discover"), "end"])
    scapy.sendp(dhcp_discover, iface=network_interface, verbose=0)
    print("DHCP Discover sent")

def analyze_dhcp_offer_and_send_decline(network_interface, transaction_id):
    def dhcp_offer(packet):
        if packet.haslayer(scapy.DHCP) and packet[scapy.DHCP].options[0][1] == 2:
            offered_ip = packet[scapy.BOOTP].yiaddr
            server_ip = packet[scapy.IP].src
            print(f"DHCP Offer received from {server_ip}, offering IP: {offered_ip}")
            send_dhcp_decline(network_interface, offered_ip, transaction_id)
            
    scapy.sniff(iface=network_interface, prn=dhcp_offer, filter="udp and (port 67 or port 68)", count=1)

def send_dhcp_decline(network_interface, offered_ip, transaction_id):
    dhcp_decline = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / \
                   scapy.IP(src="0.0.0.0", dst="255.255.255.255") / \
                   scapy.UDP(dport=67, sport=68) / \
                   scapy.BOOTP(chaddr=scapy.get_if_hwaddr(network_interface), xid=transaction_id, ciaddr=offered_ip) / \
                   scapy.DHCP(options=[("message-type", "decline"), ("requested_addr", offered_ip), "end"])
    scapy.sendp(dhcp_decline, iface=network_interface, verbose=0)
    print(f"DHCP Decline sent for offered IP: {offered_ip}")

if __name__ == "__main__":
    network, ip_address, netmask, network_interface = get_network_info()
    transaction_id = random.randint(0, 0xFFFFFFFF)
    send_dhcp_discover(network_interface, transaction_id)
    analyze_dhcp_offer_and_send_decline(network_interface, transaction_id)