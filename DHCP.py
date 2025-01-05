
# Note: for this DHCP server to work on your device, you must configure the "Manually Configured GLOBAL VARIABLES" properly.


from scapy.all import ARP, Ether, srp, sr1, ICMP, IP, conf, sniff, DHCP, BOOTP, sendp, UDP
import psutil
import socket
import ipaddress
import concurrent.futures
import csv
import os
import time
import threading

allocated_ips = {}

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
renewal_time = 72000  # 20 hrs
rebinding_time = 79200  # 22 hrs
dns_servers = ["192.168.1.1", "62.240.110.197"]
domain_name = "home"

def arp_scan(ip_range, iface):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=1, verbose=1, iface=iface, retry=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def icmp_scan(ip_range, retries=0, timeout=1):
    def ping(ip):
        for _ in range(retries):
            pkt = IP(dst=ip)/ICMP()
            reply = sr1(pkt, timeout=timeout, verbose=1)
            if reply:
                return {'ip': ip, 'mac': 'Unknown'}
        return None

    devices = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {executor.submit(ping, str(ip)): ip for ip in ipaddress.IPv4Network(ip_range).hosts()}
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            if result:
                devices.append(result)
    return devices

def save_to_csv(allocated_ips, filename='DHCP.csv'):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['IP Address', 'MAC Address', 'Lease Time', 'Renewal Time', 'Timestamp']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for ip, details in allocated_ips.items():
            writer.writerow({'IP Address': ip, 'MAC Address': details['mac'], 'Lease Time': details['lease_time'], 'Renewal Time': details['renewal_time'], 'Timestamp': details['timestamp']})


def calculate_available_ips(network):
    global allocated_ips

    allocated_ip_addresses = set(allocated_ips.keys())
    
    all_ips = set(str(ip) for ip in network.hosts())
    
    available_ips = all_ips - allocated_ip_addresses
    
    return sorted(list(available_ips))

def format_mac_address(mac_bytes):
    return ':'.join(f'{b:02x}' for b in mac_bytes[:6])

def get_local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def handle_expired_leases():
    global allocated_ips, available_ips, network

    current_time = time.time()
    expired_ips = []

    for ip, details in list(allocated_ips.items()):
        lease_end_time = details['timestamp'] + details['lease_time']
        if current_time > lease_end_time:
            expired_ips.append(ip)
            print(f"Lease for IP address {ip} has expired and is now available")

    for ip in expired_ips:
        del allocated_ips[ip]
        available_ips = calculate_available_ips(network)
        save_to_csv(allocated_ips)

def periodic_check():

    handle_expired_leases()

    global allocated_ips, available_ips, network, ip_address, netmask, network_interface

    ip_range = f"{network.network_address}/{network.prefixlen}"

    arp_devices = arp_scan(ip_range, network_interface)
    icmp_devices = icmp_scan(ip_range)

    default_lease_time = 86400  # 1 day
    default_renewal_time = 72000  # 20 hours
    default_timestamp = time.time()

    for device in arp_devices:
        ip = device['ip']
        mac = device['mac']
        if ip not in allocated_ips:
            allocated_ips[ip] = {
                'mac': mac,
                'lease_time': default_lease_time,
                'renewal_time': default_renewal_time,
                'timestamp': default_timestamp
            }
    
    for device in icmp_devices:
        ip = device['ip']
        if ip not in allocated_ips:
            allocated_ips[ip] = {
                'mac': "Unknown",
                'lease_time': default_lease_time,
                'renewal_time': default_renewal_time,
                'timestamp': default_timestamp
            }

    available_ips = calculate_available_ips(network)

    save_to_csv(allocated_ips)

    threading.Timer(600, periodic_check).start() # check every 10 minutes


def initiate():
    global allocated_ips, available_ips, network, ip_address, netmask, network_interface

    ip_range = f"{network.network_address}/{network.prefixlen}"

    print(f"Scanning network: {ip_range} on interface {network_interface}")

    arp_devices = arp_scan(ip_range, network_interface)
    icmp_devices = icmp_scan(ip_range)

    default_lease_time = 86400  # 1 day
    default_renewal_time = 72000  # 20 hours
    default_timestamp = time.time()

    for device in arp_devices:
        ip = device['ip']
        mac = device['mac']
        if ip not in allocated_ips:
            allocated_ips[ip] = {
                'mac': mac,
                'lease_time': default_lease_time,
                'renewal_time': default_renewal_time,
                'timestamp': default_timestamp
            }
    
    for device in icmp_devices:
        ip = device['ip']
        if ip not in allocated_ips:
            allocated_ips[ip] = {
                'mac': "Unknown",
                'lease_time': default_lease_time,
                'renewal_time': default_renewal_time,
                'timestamp': default_timestamp
            }

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
        requested_ip = packet[BOOTP].ciaddr
    
    if requested_ip is None or requested_ip == "0.0.0.0":
        return

    local_server_ip = get_local_ip()

    if server_id != local_server_ip and server_id is not None:
        return

    client_mac = format_mac_address(packet[BOOTP].chaddr)
    transaction_id = packet[BOOTP].xid

    if requested_ip in allocated_ips:
        # Check if the requesting client is the same as the one already allocated the IP
        if allocated_ips[requested_ip]['mac'] == client_mac:
            # Renew the lease for the existing entry
            allocated_ips[requested_ip]['lease_time'] = lease_time
            allocated_ips[requested_ip]['timestamp'] = time.time()
        else:
            handle_nak(packet)
            return
    elif requested_ip in available_ips:
        # Allocate new IP if not already allocated
        allocated_ips[requested_ip] = {
            'mac': client_mac,
            'lease_time': lease_time,
            'renewal_time': renewal_time,
            'timestamp': time.time()
        }
        available_ips.remove(requested_ip)
    else:
        # Send NAK for invalid IP address requests
        handle_nak(packet)
        return

    save_to_csv(allocated_ips)

    server_ip = local_server_ip
    router_ip = default_gateway

    ack_packet = (Ether(dst=packet[Ether].src) /
                IP(src=server_ip, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=requested_ip, siaddr=server_ip, chaddr=packet[BOOTP].chaddr[:6], xid=transaction_id) /
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
    
    print(f"ACK sent for IP address {requested_ip} to {client_mac}")


def handle_ack(packet):
    global allocated_ips, available_ips, network_interface

    ack_ip = packet[BOOTP].yiaddr
    server_ip = packet[IP].src
    client_mac = format_mac_address(packet[BOOTP].chaddr)

    if ack_ip not in allocated_ips:
            allocated_ips[ack_ip] = {
                'mac': client_mac,
                'lease_time': lease_time,
                'renewal_time': renewal_time,
                'timestamp': time.time()
            }
            available_ips = calculate_available_ips(network)
            save_to_csv(allocated_ips)
    
    print(f"ACK detected from server {server_ip} for IP address {ack_ip} to {client_mac}")


def handle_decline(packet):
    global allocated_ips, available_ips

    declined_ip = None
    for option in packet[DHCP].options:
        if option[0] == 'requested_addr':
            declined_ip = option[1]
            break

    if declined_ip and (declined_ip not in allocated_ips):
        allocated_ips[declined_ip] = {
            'mac': None,
            'lease_time': lease_time,
            'renewal_time': renewal_time,
            'timestamp': time.time()
        }

    save_to_csv(allocated_ips)
    print(f"Declined IP address {declined_ip} added to allocated IPs list")

    available_ips = calculate_available_ips(network)


def handle_nak(packet):
    global network_interface

    client_mac = packet[BOOTP].chaddr
    transaction_id = packet[BOOTP].xid
    server_ip = get_local_ip()

    nak_packet = (Ether(dst=packet[Ether].src) /
                  IP(src=server_ip, dst="255.255.255.255") /
                  UDP(sport=67, dport=68) /
                  BOOTP(op=2, yiaddr="0.0.0.0", siaddr=server_ip, chaddr=client_mac[:6], xid=transaction_id) /
                  DHCP(options=[('message-type', 'nak'),
                                ('server_id', server_ip),
                                ('end')]))

    sendp(nak_packet, iface=network_interface)
    print(f"DHCP NAK sent to {format_mac_address(client_mac)}")


def handle_release(packet):
    global allocated_ips, available_ips, network

    released_ip = packet[BOOTP].yiaddr
    client_mac = format_mac_address(packet[BOOTP].chaddr)

    if released_ip in allocated_ips:

        if allocated_ips[released_ip]['mac'] == client_mac: # Verify if the IP is actually allocated to the client releasing it
            del allocated_ips[released_ip]
            available_ips = calculate_available_ips(network)
            save_to_csv(allocated_ips)
            print(f"DHCP Release: IP address {released_ip} released by {client_mac} and is now available")

        else:
            print(f"DHCP Release: IP address {released_ip} is not allocated to {client_mac}")
    else:
        print(f"DHCP Release: IP address {released_ip} not found in allocated IPs list")

def handle_inform(packet):
    global network_interface, lease_time, renewal_time, rebinding_time, dns_servers, domain_name, default_gateway

    client_mac = packet[BOOTP].chaddr
    transaction_id = packet[BOOTP].xid
    client_ip = packet[IP].src
    server_ip = get_local_ip()

    ack_packet = (Ether(dst=packet[Ether].src) /
                  IP(src=server_ip, dst=client_ip) /
                  UDP(sport=67, dport=68) /
                  BOOTP(op=2, yiaddr=client_ip, siaddr=server_ip, chaddr=client_mac[:6], xid=transaction_id) /
                  DHCP(options=[('message-type', 'ack'),
                                ('server_id', server_ip),
                                ('lease_time', lease_time),
                                ('subnet_mask', '255.255.255.0'),
                                ('router', default_gateway),
                                ('name_server', dns_servers[0]),
                                ('name_server', dns_servers[1]),
                                ('domain', domain_name),
                                ('renewal_time', renewal_time),
                                ('rebinding_time', rebinding_time),
                                ('end')]))

    sendp(ack_packet, iface=network_interface)
    print(f"DHCP INFORM handled: Configuration sent to {format_mac_address(client_mac)}")


def dhcp_handler(packet):
    if DHCP in packet:
        dhcp_message_type = packet[DHCP].options[0][1]
        if dhcp_message_type == 1:
            handle_discover(packet)
        elif dhcp_message_type == 3:
            print("Request detected")
            handle_request(packet)
        elif dhcp_message_type == 5:
            handle_ack(packet)
        elif dhcp_message_type == 4:
            handle_decline(packet)
        elif dhcp_message_type == 7:
            handle_release(packet)
        elif dhcp_message_type == 8:
            handle_inform(packet)

def sniff_dhcp_packets(interface):
    sniff(filter="port 67 or port 68", prn=dhcp_handler, iface=interface, store=0)


if __name__ == "__main__":

    periodic_check()

    initiate()

    sniff_dhcp_packets(network_interface)