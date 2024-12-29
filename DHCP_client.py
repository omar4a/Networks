from scapy.all import *
from scapy.all import BOOTP
from scapy.layers.dhcp import DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import psutil
import ipaddress

def get_network_info():
    interfaces = psutil.net_if_addrs()
    global network_interface

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

network, ip_address, netmask, network_interface = get_network_info()

def send_dhcp_message(msg_type, mac_address, requested_ip=None, server_ip=None):

    global network_interface
    
    # Create an Ethernet frame
    ethernet = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff")
    
    # Create an IP packet
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    
    # Create a UDP packet
    udp = UDP(sport=68, dport=67)
    
    # DHCP Options
    dhcp_options = [
        ('message-type', msg_type),  # Set the DHCP message type
        ('end')
    ]
    
    if msg_type in ['request', 'decline', 'inform']:
        dhcp_options.insert(1, ('requested_addr', requested_ip))
    if server_ip:
        dhcp_options.insert(1, ('server_id', server_ip))
    
    # Create a DHCP packet
    dhcp = DHCP(options=dhcp_options)
    bootp = BOOTP(chaddr=mac_address.replace(":", ""), xid=random.randint(0, 0xFFFFFFFF))
    
    # Combine layers
    packet = ethernet / ip / udp / bootp / dhcp

    print(network_interface)
    
    # Send the packet
    sendp(packet, iface=network_interface, verbose=True)


# Example usage
mac_address = "b4:45:06:85:c2:8c"  # Replace with your MAC address
send_dhcp_message("discover", mac_address)  # DHCPDISCOVER
send_dhcp_message("request", mac_address, requested_ip="192.168.1.100")  # DHCPREQUEST
send_dhcp_message("decline", mac_address, requested_ip="192.168.1.100")  # DHCPDECLINE
#send_dhcp_message("release", mac_address, server_ip="192.168.1.1")  # DHCPRELEASE
send_dhcp_message("inform", mac_address, requested_ip="192.168.1.100")  # DHCPINFORM