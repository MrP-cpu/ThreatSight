"""Helper functions for ThreatSight"""

from colorama import Fore, Style, init
import ipaddress
import subprocess
import sys

# Initialize colorama
init(autoreset=True)

def print_banner():
    """Print colored banner"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║{Fore.GREEN}          ThreatSight - Advanced Vulnerability Scanner            {Fore.CYAN}║
{Fore.CYAN}║{Fore.YELLOW}              OS Fingerprinting | Plugin System | Threading       {Fore.CYAN}║
{Fore.CYAN}╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.2f} hours"

def get_active_interface():
    """Detect active network interface for scanning"""
    try:
        # Method 1: Try route command (macOS/Linux)
        result = subprocess.run(['route', 'get', 'default'], 
                              capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'interface:' in line:
                interface = line.split(':')[1].strip()
                if interface and interface not in ['bridge100', 'bridge0']:
                    return interface
        
        # Method 2: Check for active Wi-Fi/Ethernet on macOS
        result = subprocess.run(['networksetup', '-listallhardwareports'], 
                              capture_output=True, text=True)
        lines = result.stdout.split('\n')
        current_device = None
        for i, line in enumerate(lines):
            if 'Hardware Port: Wi-Fi' in line or 'Hardware Port: Ethernet' in line:
                if i + 1 < len(lines) and 'Device:' in lines[i + 1]:
                    current_device = lines[i + 1].split(':')[1].strip()
                    if current_device:
                        return current_device
        
        # Method 3: Fallback to first en interface
        result = subprocess.run(['ifconfig', '-l'], 
                              capture_output=True, text=True)
        interfaces = result.stdout.strip().split()
        for iface in interfaces:
            if iface.startswith('en') and iface not in ['bridge100', 'bridge0']:
                return iface
        
        return 'en0'  # Final fallback
    except Exception:
        return 'en0'

def check_interface_status(interface):
    """Check if an interface is up and has an IP"""
    try:
        result = subprocess.run(['ifconfig', interface], 
                              capture_output=True, text=True)
        return 'inet ' in result.stdout and 'status: active' in result.stdout
    except:
        return False
