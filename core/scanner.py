#!/usr/bin/env python3
import time
import nmap
import ipaddress
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

# Loading animation
for i in range(101):
    time.sleep(0.01)
    print(Fore.YELLOW + Style.BRIGHT + f"Loading ThreatSight... {i}%", end='\r')
print("\nDone!")

def print_colored_banner():
    print(Fore.CYAN + "=" * 50)
    print(Fore.GREEN + "         Welcome to ThreatSight Scanner")
    print(Fore.CYAN + "=" * 50)
    print(Fore.YELLOW + "This tool allows you to scan IP addresses for open ports and services.")
    print(Fore.YELLOW + "You can choose between SYN ACK, UDP, or Comprehensive scans.")

def scan_target(scanner, ip, ports, scan_type):
    try:
        args = {
            'syn': '-Pn -v -sS',
            'udp': '-Pn -v -sU',
            'comprehensive': '-Pn -v -sS -sV -O -A'
        }.get(scan_type, '-Pn -v -sS')

        scanner.scan(ip, ports, args)
        if ip in scanner.all_hosts():
            return ip, scanner[ip]
        else:
            return ip, f"No results returned for {ip}."
    except Exception as e:
        return ip, str(e)

def threaded_scan(ips, ports, scan_type, max_threads=10):
    results = {}
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_target, nmap.PortScanner(), ip, ports, scan_type): ip
            for ip in ips
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                target_ip, result = future.result()
                if isinstance(result, str):
                    print(Fore.RED + f"Scan failed for {ip}: {result}")
                else:
                    results[target_ip] = result
            except Exception as e:
                print(Fore.RED + f"Exception for {ip}: {str(e)}")
    return results

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_port_range():
    ports = input("Enter port range (e.g. 1-1000) or leave blank for default (1-1024): ")
    return ports if ports else '1-1024'

def scan_ping(scanner, ip):
    try:
        scanner.scan(hosts=ip, arguments='-sn')
        return scanner.all_hosts()
    except Exception as e:
        print(Fore.YELLOW + f"Discovery error: {str(e)}")
        return []

def scan_syn(scanner, ip, ports):
    scanner.scan(ip, ports, '-Pn -v -sS')
    if ip in scanner.all_hosts():
        return scanner[ip]
    else:
        raise Exception(f"No results returned for {ip}.")

def scan_udp(scanner, ip, ports):
    scanner.scan(ip, ports, '-Pn -v -sU')
    if ip in scanner.all_hosts():
        return scanner[ip]
    else:
        raise Exception(f"No results returned for {ip}.")

def scan_comprehensive(scanner, ip, ports):
    scanner.scan(ip, ports, '-Pn -v -sS -sV -O -A')
    if ip in scanner.all_hosts():
        return scanner[ip]
    else:
        raise Exception(f"No results returned for {ip}.")

def print_scan_results(scanner, ip):
    print("Scan Info:", scanner.scaninfo())
    print("IP Status:", scanner[ip].state())
    print("Protocols Found:", scanner[ip].all_protocols())
    for proto in scanner[ip].all_protocols():
        print(f"\nProtocol: {proto.upper()}")
        for port in scanner[ip][proto].keys():
            print(f"Port: {port}, State: {scanner[ip][proto][port]['state']}")

def main():
    print_colored_banner()
    scanner = nmap.PortScanner()
    print(Fore.GREEN + "Host is up. Proceeding with scan...")

    while True:
        ip_addr = input("\nEnter IP (or 'q' to exit): ").strip()
        if ip_addr.lower() == 'q':
            break

        if not validate_ip(ip_addr):
            print(Fore.RED + "Invalid IP address format.")
            continue

        live_hosts = scan_ping(scanner, ip_addr)
        if not live_hosts:
            print(Fore.YELLOW + "Host appears to be down or not responding to ping.")
            proceed = input("Do you want to continue with scan anyway? (y/n): ").strip().lower()
            if proceed != 'y':
                continue

        print("Nmap version:", scanner.nmap_version())

        print("""
Choose your scan type:
    1) SYN ACK Scan
    2) UDP Scan
    3) Comprehensive Scan
""")
        choice = input("Enter your choice (1/2/3): ").strip()
        ports = get_port_range()

        # Multiple IPs can be scanned at once
        ips = [ip.strip() for ip in ip_addr.split(',')]

        # Scan type string for threaded_scan()
        scan_type = {
            '1': 'syn',
            '2': 'udp',
            '3': 'comprehensive'
        }.get(choice)

        if not scan_type:
            print(Fore.RED + "Invalid scan option. Please choose 1, 2, or 3.")
            continue

        results = threaded_scan(ips, ports, scan_type=scan_type)

        for ip in results:
            print(Fore.CYAN + f"\nResults for {ip}:")
            try:
                print_scan_results(results[ip], ip)
            except Exception as e:
                print(Fore.RED + f"Error printing results for {ip}: {e}")

if __name__ == "__main__":
    main()

