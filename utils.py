from scapy.all import sr1, TCP, IP
from arp_v1 import arp_scan, get_default_interface_and_ip_range
from colorama import Fore, Style, init


def port_scan(ip, mac, ports):
    open_ports = []
    for port in ports:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=False)
        if response and response[TCP].flags == "SA":
            open_ports.append(port)
    
    return open_ports


def scan_devices_for_ports(devices, ports=[]):
    for device in devices:
        ip = device["ip"]
        mac = device["mac"]
        print(f"Scanning {ip} ({mac}) for open ports...")
        open_ports = port_scan(ip, mac, ports)
        device["open_ports"] = open_ports
        if open_ports:
            print(Fore.GREEN + f"Open ports on {ip} ({mac}): {open_ports}" + Style.RESET_ALL)
        else:
            continue
            # print(Fore.RED + f"No open ports found on {ip} ({mac})" + Style.RESET_ALL)
    return devices


def main():
    init(autoreset=True)

    interface, ip = get_default_interface_and_ip_range()
    print('' + Fore.YELLOW + "Starting ARP scan..." + Style.RESET_ALL)
    print('' + Fore.YELLOW + "This may take a while..." + Style.RESET_ALL)
    print('' + Fore.YELLOW + "Please wait..." + Style.RESET_ALL)
    print(f"Interface: {interface}")
    print(f"IP: {ip}")
    devices = arp_scan(ip, interface)
    open_ports = scan_devices_for_ports(devices, ports=[22, 23, 80, 443])
    print(Fore.YELLOW + "Scan complete!" + Style.RESET_ALL)
    

if __name__ == "__main__":
    main()
