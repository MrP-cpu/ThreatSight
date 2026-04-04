"""Helper functions for ThreatSight"""

from colorama import Fore, Style, init
init(autoreset=True)

def print_banner():
    """Print colored banner"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
{Fore.CYAN}║{Fore.GREEN}          ThreatSight - Advanced Vulnerability Scanner      {Fore.CYAN}║
{Fore.CYAN}║{Fore.YELLOW}              OS Fingerprinting | Plugin System              {Fore.CYAN}║
{Fore.CYAN}╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def validate_ip(ip: str) -> bool:
    """Validate IP address"""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
