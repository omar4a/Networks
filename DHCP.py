
# Note: for this DHCP server to work on your device, you must configure the "Manually Configured GLOBAL VARIABLES" properly.


from scapy.all import ARP, Ether, srp, sr1, ICMP, IP, conf, sniff, DHCP, BOOTP, sendp, UDP
import psutil
import socket
import ipaddress
import concurrent.futures
import csv
import os

allocated_ips = []
available_ips = []

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

def get_default_gateway():
    gws = psutil.net_if_stats()
    for interface, stats in gws.items():
        if stats.isup:
            addrs = psutil.net_if_addrs()[interface]
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    for gw in psutil.net_if_stats():
                        if gw == interface and psutil.net_if_stats()[gw].isup:
                            try:
                                routes = psutil.net_if_addrs()[interface]
                                for route in routes:
                                    if route.family == socket.AF_INET and not route.address.startswith("169.254"):
                                        command = "route print"
                                        process = os.popen(command)
                                        output = process.read()
                                        process.close()
                                        for line in output.splitlines():
                                            if "0.0.0.0" in line:
                                                default_gateway = line.split()[2]
                                                return default_gateway
                            except KeyError:
                                continue
    raise RuntimeError("Default gateway not found")

# GLOBAL VARIABLES
network, ip_address, netmask, network_interface = get_network_info()
default_gateway = get_default_gateway()
# Manually Configured GLOBAL VARIABLES
lease_time = 86400  # 1 day
renewal_time = 72000  # 20
rebinding_time = 79200  # 22
dns_servers = ["192.168.1.1", "62.240.110.197"]
domain_name = "home"

def arp_scan(ip_range, iface):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=1, iface=iface, retry=2)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def icmp_scan(ip_range, retries=1, timeout=1):
    def ping(ip):
        for _ in range(retries):
            pkt = IP(dst=ip)/ICMP()
            reply = sr1(pkt, timeout=timeout, verbose=1)
            if reply:
                return {'ip': ip, 'mac': 'Unknown'}
        return None

    devices = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {executor.submit(ping, str(ip)): ip for ip in ipaddress.IPv4Network(ip_range).hosts()}
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            if result:
                devices.append(result)
    return devices

def save_to_csv(allocated_ips, filename='DHCP.csv'):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['IP Address']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for ip in allocated_ips:
            writer.writerow({'IP Address': ip})

def calculate_available_ips(network):
    global allocated_ips

    allocated_ip_addresses = set(allocated_ips)
    
    all_ips = set(str(ip) for ip in network.hosts())
    
    available_ips = all_ips - allocated_ip_addresses
    
    return sorted(list(available_ips))

def format_mac_address(mac_bytes):
    return ':'.join(f'{b:02x}' for b in mac_bytes[:6])

def get_local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip


def initiate():

    global allocated_ips, available_ips, network, ip_address, netmask, network_interface

    ip_range = f"{network.network_address}/{network.prefixlen}"

    print(f"Scanning network: {ip_range} on interface {network_interface}")

    arp_devices = arp_scan(ip_range, network_interface)
    icmp_devices = icmp_scan(ip_range)


    allocated_ips.extend(device['ip'] for device in arp_devices)
    allocated_ips.extend(device['ip'] for device in icmp_devices if device['ip'] not in allocated_ips)

    available_ips = calculate_available_ips(network)

    save_to_csv(allocated_ips)

    print("\nServer is now running.")

def handle_discover(packet):
    global allocated_ips, available_ips, network_interface
    global lease_time, renewal_time, rebinding_time, dns_servers, domain_name

    requested_ip = None
    for option in packet[DHCP].options:
        if option[0] == 'requested_addr':
            requested_ip = option[1]
            break
    
    if requested_ip and (requested_ip not in allocated_ips):
        offer_ip = requested_ip
    else:
        if available_ips:
            offer_ip = available_ips[0]
        else:
            print("No available IP addresses to offer")
            return

    server_ip = get_local_ip()
    router_ip = default_gateway
    client_mac = packet[BOOTP].chaddr
    transaction_id = packet[BOOTP].xid

    offer_packet = (Ether(dst=packet[Ether].src) /
                IP(src=server_ip, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=offer_ip, siaddr=server_ip, chaddr=client_mac[:6], xid=transaction_id) /
                DHCP(options=[('message-type', 'offer'),
                            ('server_id', server_ip),
                            ('lease_time', lease_time),
                            ('subnet_mask', '255.255.255.0'),
                            ('router', router_ip),
                            ('name_server', dns_servers[0]),
                            ('name_server', dns_servers[1]),
                            ('domain', domain_name),
                            ('renewal_time', renewal_time),
                            ('rebinding_time', rebinding_time),
                            ('end')]))
    
    sendp(offer_packet, iface=network_interface)
    
    mac_address = format_mac_address(packet[BOOTP].chaddr)
    print(f"Offered IP address {offer_ip} to {mac_address}")

def format_mac_address(mac_bytes):
    return ':'.join(f'{b:02x}' for b in mac_bytes[:6])



def handle_request(packet):
    global allocated_ips, available_ips, network_interface, default_gateway
    global lease_time, renewal_time, rebinding_time, dns_servers, domain_name

    requested_ip = None
    server_id = None
    for option in packet[DHCP].options:
        if option[0] == 'requested_addr':
            requested_ip = option[1]
        elif option[0] == 'server_id':
            server_id = option[1]

    if requested_ip is None:
        print("No requested IP found in DHCP options")
        return

    local_server_ip = get_local_ip()

    if server_id != local_server_ip:
        return

    client_mac = packet[BOOTP].chaddr
    transaction_id = packet[BOOTP].xid

    if requested_ip and (requested_ip not in allocated_ips):
        ack_ip = requested_ip
    else:
        print("Requested IP not found or already allocated")
        return

    server_ip = local_server_ip
    router_ip = default_gateway

    ack_packet = (Ether(dst=packet[Ether].src) /
                IP(src=server_ip, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=ack_ip, siaddr=server_ip, chaddr=client_mac[:6], xid=transaction_id) /
                DHCP(options=[('message-type', 'ack'),
                            ('server_id', server_ip),
                            ('lease_time', lease_time),
                            ('subnet_mask', '255.255.255.0'),
                            ('router', router_ip),
                            ('name_server', dns_servers[0]),
                            ('name_server', dns_servers[1]),
                            ('domain', domain_name),
                            ('renewal_time', renewal_time),
                            ('rebinding_time', rebinding_time),
                            ('end')]))

    sendp(ack_packet, iface=network_interface)
    
    mac_address = format_mac_address(packet[BOOTP].chaddr)

def handle_ack(packet):
    global allocated_ips, available_ips, network_interface

    ack_ip = packet[BOOTP].yiaddr
    server_ip = packet[IP].src
    client_mac = format_mac_address(packet[BOOTP].chaddr)

    if ack_ip not in allocated_ips:
        allocated_ips.append(ack_ip)
        available_ips = calculate_available_ips(network)
        save_to_csv(allocated_ips)
    
    print(f"ACK detected from server {server_ip} for IP address {ack_ip} to {client_mac}")


def handle_decline(packet):
    print(f"DHCP Decline")

def handle_nak(packet):
    print(f"DHCP NAK")

def handle_release(packet):
    print(f"DHCP Release")

def handle_inform(packet):
    print(f"DHCP Inform")

def dhcp_handler(packet):
    if DHCP in packet:
        dhcp_message_type = packet[DHCP].options[0][1]
        if dhcp_message_type == 1:
            handle_discover(packet)
        elif dhcp_message_type == 3:
            handle_request(packet)
        elif dhcp_message_type == 5:
            handle_ack(packet)
        elif dhcp_message_type == 4:
            handle_decline(packet)
        elif dhcp_message_type == 6:
            handle_nak(packet)
        elif dhcp_message_type == 7:
            handle_release(packet)
        elif dhcp_message_type == 8:
            handle_inform(packet)

def sniff_dhcp_packets(interface):
    sniff(filter="port 67 or port 68", prn=dhcp_handler, iface=interface, store=0)


if __name__ == "__main__":

    initiate()

    sniff_dhcp_packets(network_interface)



"""
Phase 3:
- Add handling functionalities for DHCP Decline, NAK, Release, & Inform messages.
- save_to_csv should be improved. Needs to include mac addresses, lease time, renewal time, and timestamps.
  Also need to update values periodically even if the DHCP server was not invoked.
- Add functionality  

"""

"""
Performance Improvements:
    - arp_scan & icmp_scan can be more efficient. Retries & timeout can be optimized. icmp multithreading can be optimized.
    - allocated_ips & available_ips can potentially be changed from lists to dictionaries or another appropriate data structure. Appropriate changes must be made throughout all the code.
    - Is there a way to find DNS servers dynamically instead of manual configuration?
    - For some reason it takes the client several discover messages before an offer is accepted from this server.
"""