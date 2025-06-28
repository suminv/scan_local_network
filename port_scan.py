import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import sr1, TCP, IP, Ether, srp, ARP
from colorama import Fore, Style, init
from tqdm import tqdm
import netifaces
import os
from arp_scanner import update_vendor_database, get_vendor

DEFAULT_PORTS = [22, 23, 80, 443, 8080]
MAX_WORKERS = 20

def arp_scan(ip_range, interface):
    """Performs an ARP scan to discover devices on the network."""
    try:
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered, _ = srp(packet, timeout=2, verbose=False, iface=interface)
        return [{"ip": rcv.psrc, "mac": rcv.hwsrc} for _, rcv in answered]
    except Exception as e:
        print(f"{Fore.RED}Error during ARP scan: {e}{Style.RESET_ALL}", file=sys.stderr)
        return []

def scan_single_port(ip, port):
    """Scans a single port on a given IP.

    Args:
        ip (str): The IP address to scan.
        port (int): The port to scan.

    Returns:
        int: The port number if it's open, otherwise None.
    """
    try:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=False)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            return port
    except Exception:
        return None
    return None

def scan_ports_for_device(device, ports):
    """Scans a list of ports for a single device using a thread pool.

    Args:
        device (dict): A dictionary representing the device, including its IP address.
        ports (list): A list of ports to scan.

    Returns:
        dict: The device dictionary updated with a list of open ports.
    """
    ip = device["ip"]
    open_ports = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_port = {executor.submit(scan_single_port, ip, port): port for port in ports}
        for future in as_completed(future_to_port):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    device["open_ports"] = sorted(open_ports)
    return device

def get_default_interface_and_ip_range():
    """Automatically detects the default network interface and IP range.

    Returns:
        tuple: A tuple containing the interface name and the IP range in CIDR notation.
    """
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET]
        interface = default_gateway[1]
        iface_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        ip = iface_info['addr']
        netmask = iface_info['netmask']
        netmask_bits = sum(bin(int(x)).count('1') for x in netmask.split('.'))
        ip_range = f"{ip}/{netmask_bits}"
        return interface, ip_range
    except Exception as e:
        raise RuntimeError(f"Failed to detect network settings: {e}")

def parse_ports(port_string):
    """Parses a comma-separated string of ports and ranges (e.g., '22,80,100-200').

    Args:
        port_string (str): The string of ports to parse.

    Returns:
        list: A sorted list of integers representing the ports.
    """
    ports = set()
    if not port_string:
        return DEFAULT_PORTS
    try:
        parts = port_string.split(',')
        for part in parts:
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        return sorted(list(ports))
    except ValueError:
        raise ValueError("Invalid port format. Use comma-separated values and ranges (e.g., '22,80,100-200').")

def main():
    """Main function to run the port scanner."""
    init(autoreset=True)
    parser = argparse.ArgumentParser(description="Network Port Scanner")
    parser.add_argument("-p", "--ports", type=str, help=f"Ports to scan (e.g., '22,80,443' or '1-1024'). Defaults to scanning popular ports.")
    args = parser.parse_args()
    try:
        ports_to_scan = parse_ports(args.ports)
    except ValueError as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)
    print(f"{Fore.CYAN}--- Port Scanner ---{Style.RESET_ALL}")
    mac_lookup = update_vendor_database()
    try:
        interface, ip_range = get_default_interface_and_ip_range()
        print(f"Using interface: {Fore.YELLOW}{interface}{Style.RESET_ALL}")
        print(f"Scanning IP range: {Fore.YELLOW}{ip_range}{Style.RESET_ALL}")
    except RuntimeError as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)
    print("\nDiscovering devices on the network...")
    devices = arp_scan(ip_range, interface)
    if not devices:
        print(f"{Fore.YELLOW}No devices found on the network.{Style.RESET_ALL}")
        return
    print("Looking up vendor information...")
    for device in devices:
        device['vendor'] = get_vendor(device['mac'], mac_lookup)
    print(f"Found {len(devices)} devices. Now scanning for open ports...")
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_device = {executor.submit(scan_ports_for_device, device, ports_to_scan): device for device in devices}
        for future in tqdm(as_completed(future_to_device), total=len(devices), desc="Overall Progress"):
            results.append(future.result())
    print(f"\n{Fore.CYAN}--- Scan Results ---{Style.RESET_ALL}")
    found_any_ports = False
    for device in sorted(results, key=lambda x: x['ip']):
        if device["open_ports"]:
            found_any_ports = True
            ports_str = ', '.join(map(str, device['open_ports']))
            vendor_str = f"({device.get('vendor', 'Unknown')})"
            print(f"  {Fore.GREEN}Device:{Style.RESET_ALL} {device['ip']} {Fore.CYAN}{vendor_str}{Style.RESET_ALL} ({device['mac']})")
            print(f"    {Fore.GREEN}Open Ports:{Style.RESET_ALL} {ports_str}")
    if not found_any_ports:
        print(f"{Fore.YELLOW}No open ports found on any of the discovered devices.{Style.RESET_ALL}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{Fore.RED}Error: This script requires root/administrator privileges.{Style.RESET_ALL}", file=sys.stderr)
        print(f"{Fore.RED}Please run with 'sudo'.{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)
    main()
