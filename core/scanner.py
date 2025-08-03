#!/usr/bin/env python3
import time
import nmap
import ipaddress
from pprint import pprint
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed


# Initialize colorama
init(autoreset=True)


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



def scan_target(ip, ports, scan_type):
    """Thread-safe Scanning function"""
    try:
        if scan_type=='syn':
            scanner.scan(ip, ports, '-v -sS')
        elif scan_type=='udp':
            scanner.scan(ip, ports, '-v -sU')
        elif scan_type=='comprehensive':
            scanner.scan(ip, ports, '-v -sS -sV -O -A')
        else:
            raise ValueError("Invalid scan type specified.")
        return scanner[ip]
    except Exception as e:
        print(Fore.RED + f"Error scanning {ip}: {e}")
        return None
    

def threaded_scan(ips, ports, scan_type, max_threads=10):
    results = {}
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Create a future for each IP scan
        futures = {
            executor.submit(scan_target, nmap.PortScanner(), ip, ports, scan_type): ip 
            for ip in ips
        }
        
        # Process completed scans
        for future in as_completed(futures):
            ip = futures[future]
            try:
                target_ip, result = future.result()
                if isinstance(result, str):  # If error
                    print(Fore.RED + f"Scan failed for {ip}: {result}")
                else:
                    results[target_ip] = result  # Store success
            except Exception as e:
                print(Fore.RED + f"Exception for {ip}: {str(e)}")
    
    return results


# Function to validate IP address format

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
    """Reliable host discovery with multiple techniques"""
    try:
        # Try comprehensive discovery first
        scanner.scan(hosts=ip, arguments='-sn -PE -PS443,80 -PA21,22')
        hosts = scanner.all_hosts()
        
        if not hosts:
            # Fallback to just ICMP
            scanner.scan(hosts=ip, arguments='-sn -PE')
            hosts = scanner.all_hosts()
            
        return hosts
    except Exception as e:
        print(Fore.YELLOW + f"Discovery error: {str(e)}")
        return []

def scan_syn(scanner, ip, ports):
    scanner.scan(ip, ports, '-v -sS')
    return scanner[ip]

def scan_udp(scanner, ip, ports):
    scanner.scan(ip, ports, '-v -sU')
    return scanner[ip]

def scan_comprehensive(scanner, ip, ports):
    scanner.scan(ip, ports, '-v -sS -sV -O -A')
    return scanner[ip]

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

        if not scan_ping(scanner, ip_addr):
            print(Fore.YELLOW + "Host appears to be down.")
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

        if choice == '1':
            result = scan_syn(scanner, ip_addr, ports)
            print_scan_results(scanner, ip_addr)
        elif choice == '2':
            result = scan_udp(scanner, ip_addr, ports)
            print_scan_results(scanner, ip_addr)
        elif choice == '3':
            result = scan_comprehensive(scanner, ip_addr, ports)
            print_scan_results(scanner, ip_addr)
        else:
            print(Fore.RED + "Invalid scan option. Please choose 1, 2, or 3.")

if __name__ == "__main__":
    main()
