#!/usr/bin/env python3
"""ThreatSight CLI - Main Entry Point"""

import click
import sys
from pathlib import Path
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Add parent directory to path for development
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from threatsight.core.scanner import ThreatScanner
from threatsight.core.os_fingerprint import OSFingerprintDB
from threatsight.utils.helpers import print_banner, get_active_interface

@click.group()
def cli():
    """ThreatSight - Advanced Network Vulnerability Scanner"""
    print_banner()

@cli.command()
@click.option('--target', '-t', required=True, help='Target IP or hostname')
@click.option('--ports', '-p', default='1-1024', help='Port range to scan')
@click.option('--scan-type', '-s', default='syn', 
              type=click.Choice(['syn', 'udp', 'comprehensive']),
              help='Type of scan to perform')
@click.option('--threads', '-T', default=10, help='Number of threads', show_default=True)
def scan(target, ports, scan_type, threads):
    """Perform network scan on target"""
    
    # Show interface being used
    interface = get_active_interface()
    
    click.echo(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    click.echo(f"{Fore.YELLOW}[*] Target: {target}{Style.RESET_ALL}")
    click.echo(f"[*] Ports: {ports}")
    click.echo(f"[*] Scan Type: {scan_type.upper()}")
    click.echo(f"[*] Threads: {threads}")
    click.echo(f"[*] Interface: {interface}")
    click.echo(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
    
    scanner = ThreatScanner()
    
    try:
        # Perform scan
        results = scanner.scan_target_with_os(target, ports, scan_type)
        
        if target not in results:
            click.echo(f"{Fore.RED}[-] No results returned{Style.RESET_ALL}")
            return
        
        scan_data = results[target]
        
        # Check for errors
        if 'error' in scan_data:
            click.echo(f"{Fore.RED}[-] Error: {scan_data['error']}{Style.RESET_ALL}")
            return
        
        # Check if host is reachable
        if not scan_data.get('reachable', False):
            click.echo(f"{Fore.YELLOW}[!] Host {target} did not respond{Style.RESET_ALL}")
            return
        
        # Display host status
        status_color = Fore.GREEN if scan_data.get('status') == 'up' else Fore.RED
        click.echo(f"{status_color}[+] Host Status: {scan_data.get('status', 'unknown')}{Style.RESET_ALL}")
        
        # Display open ports
        open_ports = scan_data.get('open_ports', {})
        if open_ports:
            click.echo(f"\n{Fore.GREEN}[+] Open Ports Found: {len(open_ports)}{Style.RESET_ALL}")
            click.echo(f"{Fore.CYAN}{'-'*40}{Style.RESET_ALL}")
            
            for port_key, port_info in open_ports.items():
                service = port_info.get('service', 'unknown')
                version = f" ({port_info.get('version', '')})" if port_info.get('version') else ''
                click.echo(f"  {Fore.GREEN}{port_key:<12}{Style.RESET_ALL} {service}{version}")
        else:
            click.echo(f"\n{Fore.YELLOW}[!] No open ports found in range {ports}{Style.RESET_ALL}")
        
        # Display filtered ports (firewall blocking)
        filtered_ports = scan_data.get('filtered_ports', {})
        if filtered_ports:
            click.echo(f"\n{Fore.MAGENTA}[!] Filtered/Blocked Ports: {len(filtered_ports)}{Style.RESET_ALL}")
            click.echo(f"{Fore.CYAN}{'-'*40}{Style.RESET_ALL}")
            for port_key in list(filtered_ports.keys())[:10]:  # Show first 10
                click.echo(f"  {Fore.MAGENTA}{port_key:<12}{Style.RESET_ALL} (firewall)")
            if len(filtered_ports) > 10:
                click.echo(f"  ... and {len(filtered_ports) - 10} more")
        
        # OS Detection for comprehensive scans
        if scan_type == 'comprehensive' and 'os_matches' in scan_data:
            click.echo(f"\n{Fore.CYAN}[+] Operating System Detection:{Style.RESET_ALL}")
            click.echo(f"{Fore.CYAN}{'-'*40}{Style.RESET_ALL}")
            
            os_matches = scan_data.get('os_matches', [])
            if os_matches:
                for osm in os_matches[:3]:
                    accuracy = osm.get('accuracy', 0)
                    acc_color = Fore.GREEN if accuracy > 80 else Fore.YELLOW if accuracy > 50 else Fore.RED
                    click.echo(f"  {acc_color}{osm.get('name', 'Unknown')} (Accuracy: {accuracy}%){Style.RESET_ALL}")
            
            # Custom OS fingerprinting
            tcp_fingerprint = scan_data.get('tcp_fingerprint', {})
            if tcp_fingerprint:
                os_info = OSFingerprintDB.find_match(
                    ttl=tcp_fingerprint.get('ttl', 64),
                    window_size=tcp_fingerprint.get('window_size', 64240),
                    df=tcp_fingerprint.get('df', True),
                    options=tcp_fingerprint.get('options', [])
                )
                
                if os_info.get('os') != 'Unknown':
                    click.echo(f"\n  {Fore.MAGENTA}[Custom Database]{Style.RESET_ALL}")
                    click.echo(f"    OS: {os_info.get('os', 'Unknown')}")
                    click.echo(f"    Confidence: {os_info.get('final_confidence', 0)}%")
        
        click.echo(f"\n{Fore.GREEN}[✓] Scan completed successfully{Style.RESET_ALL}")
        
    except Exception as e:
        click.echo(f"{Fore.RED}[-] Scan failed: {str(e)}{Style.RESET_ALL}")

@cli.command()
@click.option('--target', '-t', required=True, help='Target IP or hostname')
def quick(target):
    """Quick scan of common ports (22,80,443,3389,8080)"""
    click.echo(f"\n{Fore.YELLOW}[*] Quick scanning {target} for common ports{Style.RESET_ALL}")
    
    scanner = ThreatScanner()
    common_ports = '22,80,443,3389,8080,8443'
    
    results = scanner.scan_target_with_os(target, common_ports, 'syn')
    
    if target in results:
        scan_data = results[target]
        open_ports = scan_data.get('open_ports', {})
        
        if open_ports:
            click.echo(f"{Fore.GREEN}[+] Open ports found:{Style.RESET_ALL}")
            for port_key in open_ports:
                click.echo(f"    {port_key}")
        else:
            click.echo(f"{Fore.YELLOW}[!] No common open ports found{Style.RESET_ALL}")

@cli.command()
def version():
    """Show ThreatSight version"""
    from threatsight import __version__
    click.echo(f"ThreatSight version {__version__}")

@cli.command()
def info():
    """Display information about ThreatSight"""
    interface = get_active_interface()
    click.echo(f"""
{Fore.CYAN}ThreatSight - Advanced Network Vulnerability Scanner{Style.RESET_ALL}

{Fore.YELLOW}Capabilities:{Style.RESET_ALL}
  • SYN, UDP, and Comprehensive scanning
  • OS fingerprinting with 11+ OS signatures
  • Multi-threaded batch scanning
  • Plugin system for extensibility

{Fore.YELLOW}Scan Types:{Style.RESET_ALL}
  • syn: Stealth SYN scan for TCP ports
  • udp: UDP service discovery
  • comprehensive: Full scan with version detection and OS fingerprinting

{Fore.YELLOW}Current Configuration:{Style.RESET_ALL}
  • Active Interface: {interface}

{Fore.YELLOW}Examples:{Style.RESET_ALL}
  threatsight scan -t 192.168.1.1 -p 1-1000 -s syn
  sudo threatsight scan -t 192.168.1.1 -s comprehensive
  threatsight quick -t 192.168.1.1
{Style.RESET_ALL}
""")

if __name__ == "__main__":
    cli()
