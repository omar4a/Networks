import scapy.all as scapy
import random
import socket
import psutil

def get_network_interface():
    interfaces = psutil.net_if_addrs()
    network_interface = None

    for interface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("169.254"):
                network_interface = interface
                break
        if network_interface:
            break

    if network_interface is None:
        raise ValueError("Unable to determine network interface")

    return network_interface

def send_dhcp_inform(network_interface, ip_address):
    transaction_id = random.randint(0, 0xFFFFFFFF)
    dhcp_inform = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / \
                  scapy.IP(src=ip_address, dst="255.255.255.255") / \
                  scapy.UDP(dport=67, sport=68) / \
                  scapy.BOOTP(chaddr=scapy.get_if_hwaddr(network_interface), xid=transaction_id, ciaddr=ip_address) / \
                  scapy.DHCP(options=[("message-type", "inform"), ("param_req_list", [1, 3, 6, 15]), "end"])
    scapy.sendp(dhcp_inform, iface=network_interface, verbose=0)
    print("DHCP INFORM sent")

if __name__ == "__main__":
    ip_address = "192.168.1.250"
    network_interface = get_network_interface()
    send_dhcp_inform(network_interface, ip_address)