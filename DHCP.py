from scapy.all import ARP, Ether, srp, sr1, ICMP, IP, conf, sniff, DHCP, BOOTP
import psutil
import socket
import ipaddress
import concurrent.futures
import csv

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
        fieldnames = ['IP Address', 'MAC Address']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for ip_info in allocated_ips:
            writer.writerow({'IP Address': ip_info['ip'], 'MAC Address': ip_info['mac']})

def initiate():
    network, ip_address, netmask, network_interface = get_network_info()
    ip_range = f"{network.network_address}/{network.prefixlen}"

    print(f"Scanning network: {ip_range} on interface {network_interface}")

    arp_devices = arp_scan(ip_range, network_interface)
    icmp_devices = icmp_scan(ip_range)

    allocated_ips = {device['ip']: device for device in arp_devices}
    for device in icmp_devices:
        if device['ip'] not in allocated_ips:
            allocated_ips[device['ip']] = device

    allocated_ips_list = list(allocated_ips.values())

    save_to_csv(allocated_ips_list)


def handle_discover(packet):
    print(f"DHCP Discover")

def handle_offer(packet):
    print(f"DHCP Offer")

def handle_request(packet):
    print(f"DHCP Request")

def handle_ack(packet):
    print(f"DHCP ACK")

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
        elif dhcp_message_type == 2:
            handle_offer(packet)
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

    network, ip_address, netmask, network_interface = get_network_info()

    initiate()

    sniff_dhcp_packets(network_interface)