#!/usr/bin/env python3
import time
import nmap
import socket
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
        print(f"Thread started for {ip}")
        args = {
            'syn': '-sS',
            'udp': '-sU',
            'comprehensive': '-sS -sV -O -A'
        }.get(scan_type, '-sS')

        print(Fore.CYAN + f"[DEBUG] Scan issued for {ip} on ports {ports} with args: {args}")
        scanner.scan(ip, ports, arguments=args)

        if ip in scanner.all_hosts():
            print(Fore.GREEN + f"[✓] Thread completed successfully for {ip}")
            return ip, scanner[ip]
        else:
            print(Fore.YELLOW + f"[!] Thread completed but no results for {ip}")
            # Optional: return raw output for debugging
            return ip, scanner.command_line()
    except Exception as e:
        print(Fore.RED + f"[✗] Thread failed for {ip}: {e}")
        return ip, str(e)

def threaded_scan(ips, ports, scan_type, max_threads=10):
    start_time = time.time()
    results = {}
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_target, nmap.PortScanner(), ip, ports, scan_type): ip
            for ip in ips
        }

        for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning..."):
            ip = futures[future]
            try:
                target_ip, result = future.result()
                if isinstance(result, str):
                    print(Fore.RED + f"Scan failed for {ip}: {result}")
                else:
                    results[target_ip] = result
            except Exception as e:
                print(Fore.RED + f"Exception for {ip}: {str(e)}")
    end_time = time.time()
    print(f"Scan completed in {end_time - start_time:.2f} seconds")
    return results

def validate_ip(ip):
    try:
        # Handle comma-separated IPs
        if ',' in ip:
            return all(validate_ip(i.strip()) for i in ip.split(','))
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_port_range():
    ports = input("Enter port range (e.g. 1-1000) or leave blank for default (1-1024): ")
    if not ports:
        return '1-1024'
    try:
        start, end = map(int, ports.split('-'))
        if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
            return ports
        else:
            raise ValueError
    except:
        print(Fore.RED + "Invalid port range. Defaulting to 1-1024.")
        return '1-1024'


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

def os_scan(ip):
    """Detect operating system"""
    arguments = '-O --osscan-guess'
    scanner.scan(ip, arguments=arguments)
    return scanner[ip]['osmatch']


def print_scan_results(scan_result, ip):
    try:
        print(f"{Fore.CYAN}Scan results for {ip}:{Style.RESET_ALL}")
        print(f"IP Status: {scan_result.get('status', {}).get('state', 'unknown')}")
        
        protocols = scan_result.all_protocols()
        print(f"Protocols Detected: {protocols}")

        for proto in protocols:
            ports = scan_result.get(proto, {}).keys()
            print(f"\n{Fore.YELLOW}Protocol: {proto.upper()}{Style.RESET_ALL}")
            for port in sorted(ports):
                port_data = scan_result[proto][port]
                state = port_data.get('state', 'unknown')
                service = port_data.get('name', 'unknown')
                print(f"  Port: {port:<6} | State: {state:<7} | Service: {service}")
    except Exception as e:
        print(Fore.RED + f"Error while printing scan result: {e}")




def main():
    print_colored_banner()
    scanner = nmap.PortScanner()

    version = scanner.nmap_version()
    print(Fore.YELLOW + f"Nmap version: {version}")
    print(Fore.GREEN + "ThreatSight Scanner is ready to use!")


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

        for ip, result in results.items():
           print(Fore.CYAN + f"\nResults for {ip}:")
           print_scan_results(result, ip)


if __name__ == "__main__":
    main()

