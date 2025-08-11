#!/usr/bin/env python3
import time
import nmap
import socket
import ipaddress
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import signal

from tqdm.auto import tqdm  # Better auto-detection for console/Jupyter



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


def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(ip)
        return ip
    except socket.gaierror:
        print(Fore.RED + f"[!] Failed to resolve {domain}")
        return None


def signal_handler(sig, frame):
    print(Fore.RED + "\n[!] Scan interrupted by user.")
    exit(0)
signal.signal(signal.SIGINT, signal_handler)



def scan_target(scanner, ip, ports, scan_type):
    try:
        tqdm.write(f"\nThread started for {ip}")
        
        args = {
            'syn': '-sS -T4 --open',
            'udp': '-sU -T4 --max-retries 1 --min-rate 500 --top-ports 100',  # Scan top 100 UDP ports
            'comprehensive': '-sS -sV -O -A -T4',
            'os': '-O --osscan-guess'  # New OS scan type

        }.get(scan_type, '-sS -T4')

        tqdm.write(Fore.CYAN + f"[*] Scanning {ip}:{ports} ({scan_type})")
        
        start_time = time.time()
        scanner.scan(ip, ports, arguments=args)
        scan_duration = time.time() - start_time

        if ip not in scanner.all_hosts():
            return ip, {'status': 'failed', 'error': 'No response from host'}

        result = scanner[ip]
        open_ports = []
        
        # Safely get open ports
        for proto in result.all_protocols():
            open_ports.extend([port for port in result[proto] if result[proto][port]['state'] == 'open'])

        tqdm.write(Fore.GREEN + 
            f"[✓] Scan completed in {scan_duration:.2f}s\n"
            f"    Open ports found: {len(open_ports)}")
        
        return ip, result
        
    except nmap.PortScannerError as e:
        error_msg = f"Nmap error: {str(e)}"
        tqdm.write(Fore.RED + f"[✗] {error_msg}")
        return ip, {'status': 'failed', 'error': error_msg}
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        tqdm.write(Fore.RED + f"[✗] {error_msg}")
        return ip, {'status': 'failed', 'error': error_msg}
    
def threaded_scan(scanner, ips, ports, scan_type, max_threads=5):
    start_time = time.time()
    results = {}
    
    with tqdm(total=len(ips), desc="Overall Progress") as pbar:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {
                executor.submit(scan_target, scanner, ip, ports, scan_type): ip
                for ip in ips
            }

            for future in as_completed(futures):
                ip = futures[future]
                try:
                    target_ip, result = future.result()
                    results[target_ip] = result
                except Exception as e:
                    tqdm.write(Fore.RED + f"Error for {ip}: {str(e)}")
                finally:
                    pbar.update(1)  # Update progress bar for each completed scan

    end_time = time.time()
    tqdm.write(f"\nScan completed in {end_time - start_time:.2f} seconds")
    return results

def validate_target(target):
    """Check if input is IP or domain, return resolved IP(s)"""
    try:
        # Handle comma-separated targets
        if ',' in target:
            return [validate_target(t.strip()) for t in target.split(',')]
        
        # First try if it's a valid IP
        ipaddress.ip_address(target)
        return target
    except ValueError:
        # If not IP, try domain resolution
        try:
            ip = socket.gethostbyname(target)
            print(Fore.GREEN + f"Resolved {target} → {ip}")
            return ip
        except socket.gaierror:
            print(Fore.RED + f"[!] Failed to resolve {target}")
            return None
        
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

def os_scan(scanner, ip):  # Pass scanner as an argument
    arguments = '-O --osscan-guess'
    scanner.scan(ip, arguments=arguments)
    return scanner[ip]['osmatch']


def print_scan_results(scan_result, ip, scanner=None):
    """Print scan results including OS information when available"""
    try:
        # Header
        print(f"\n{Fore.CYAN}=== Scan Results for {ip} ==={Style.RESET_ALL}")
        
        # Host status
        status = scan_result.get('status', {}).get('state', 'unknown')
        print(f"{Fore.GREEN}Host Status: {status}{Style.RESET_ALL}")
        
        # OS information (if available)
        if 'osmatch' in scan_result:
            print(f"\n{Fore.YELLOW}OS Detection:{Style.RESET_ALL}")
            best_os = max(scan_result['osmatch'], 
                         key=lambda x: float(x['accuracy']), 
                         default={'name':'Unknown', 'accuracy':'0'})
            print(f"  Most Likely: {best_os['name']} ({best_os['accuracy']}% accuracy)")
            
        # Port information
        protocols = scan_result.all_protocols()
        print(f"\n{Fore.YELLOW}Discovered Ports:{Style.RESET_ALL}")
        
        for proto in protocols:
            print(f"\nProtocol: {proto.upper()}")
            for port, port_data in sorted(scan_result[proto].items()):
                state = port_data['state']
                if state.lower() != 'open':
                    continue
                    
                service = port_data.get('name', 'unknown')
                product = port_data.get('product', '')
                version = port_data.get('version', '')
                extrainfo = port_data.get('extrainfo', '')
                
                service_info = f"{service} {product} {version} {extrainfo}".strip()
                print(f"  {port:<6} {state:<7} {service_info}")
                
    except Exception as e:
        print(f"{Fore.RED}Error displaying results: {e}{Style.RESET_ALL}")




def main():
    print_colored_banner()
    scanner = nmap.PortScanner()
    version = scanner.nmap_version()
    print(Fore.YELLOW + f"Nmap version: {version}")
    print(Fore.GREEN + "ThreatSight Scanner is ready to use!")

    while True:
        target = input("\nEnter target IP/domain (or 'q' to exit): ").strip()
        if target.lower() == 'q':
            break

        # Validate target (accepts IP or domain)
        validated_target = validate_target(target)
        if not validated_target:
            continue

        # Handle single target or multiple targets
        targets = [validated_target] if isinstance(validated_target, str) else validated_target

        live_hosts = scan_ping(scanner, validated_target)  # Changed from ip_addr to validated_target
        if not live_hosts:
            print(Fore.YELLOW + "Host appears to be down or not responding to ping.")
            proceed = input("Do you want to continue with scan anyway? (y/n): ").strip().lower()
            if proceed != 'y':
                continue

        print("""
Choose your scan type:
    1) SYN ACK Scan
    2) UDP Scan
    3) Comprehensive Scan
""")
        choice = input("Enter your choice (1/2/3): ").strip()
        ports = get_port_range()

        scan_type = {
            '1': 'syn',
            '2': 'udp',
            '3': 'comprehensive'
        }.get(choice)

        if not scan_type:
            print(Fore.RED + "Invalid scan option. Please choose 1, 2, or 3.")
            continue

        results = threaded_scan(scanner, targets, ports, scan_type)  # Pass scanner instance

        for ip, result in results.items():
            print(Fore.CYAN + f"\nResults for {ip}:")
            print_scan_results(result, ip)


if __name__ == "__main__":
    main()

