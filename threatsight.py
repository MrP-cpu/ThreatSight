#!/usr/bin/env python3

"""
ThreatSight - Advanced Network Reconnaissance Tool
A comprehensive port scanner with service identification and stealth capabilities
"""

import socket
import asyncio
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from tqdm import tqdm
import time
import random
import struct
import argparse
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict
import binascii
import os
import sys
import textwrap

import json
import importlib
import importlib.util
import glob
import re
from pathlib import Path



# Initialize colorama for colored output
from colorama import Fore, Style, init


# for os fingerprinting 
from core.os_fingerprint import OSFingerprintDB
init()

# ASCII Art Banner
THREATSIGHT_BANNER = f"""
{Fore.RED}
████████ ██   ██ ██████  ███████  █████  ████████ ███████ ██  ██████  ██   ██ ████████ 
   ██    ██   ██ ██   ██ ██      ██   ██    ██    ██      ██ ██       ██   ██    ██    
   ██    ███████ ██████  █████   ███████    ██    ███████ ██ ██   ███ ███████    ██    
   ██    ██   ██ ██   ██ ██      ██   ██    ██         ██ ██ ██    ██ ██   ██    ██    
   ██    ██   ██ ██   ██ ███████ ██   ██    ██    ███████ ██  ██████  ██   ██    ██    
                                                                                       
                                                                                        
                                                                                                                                        
                                                                                                                                        
{Style.RESET_ALL}
{Fore.CYAN}                       Advanced Network Reconnaissance Tool{Style.RESET_ALL}
{Fore.YELLOW}                     https://github.com/MrP-cpu/ThreatSight{Style.RESET_ALL}
"""

def display_banner():
    """Display the tool banner"""
    if not args.no_banner:
        banner = """
        ╔══════════════════════════════════════════════════════════╗
        ║                  ThreatSight v1.0                       ║
        ║          Advanced Network Reconnaissance Tool           ║
        ║                                                          ║
        ║  Comprehensive network scanning and reconnaissance      ║
        ║  with multiple scanning techniques and optimizations     ║
        ╚══════════════════════════════════════════════════════════╝
        """
        print(banner)

def display_help():
    """Display comprehensive help information"""
    help_text = """
    THREATSIGHT - ADVANCED NETWORK RECONNAISSANCE TOOL
    ==================================================

    USAGE:
      python3 threatsight.py [TARGET] [OPTIONS]
      python3 threatsight.py 192.168.1.1 -s 20 -e 1000 -t threaded
      python3 threatsight.py example.com --common --stealth

    REQUIRED ARGUMENTS:
      target                Target IP address or domain name to scan
                            Example: 192.168.1.1 or example.com

    SCANNING OPTIONS:
      -s, --start PORT      Starting port number (default: 1)
      -e, --end PORT        Ending port number (default: 1024)
      -t, --type TYPE       Scanning approach type:
                            - threaded: Multi-threaded scanning (default)
                            - process: Multi-process scanning
                            - async: Asynchronous I/O scanning
                            - benchmark: Performance benchmarking mode

    ADVANCED SCANNING MODES:
      --syn                 Use SYN scan (half-open) instead of TCP connect
                            Requires root/administrator privileges
      --stealth             Enable stealth mode (slower, less detectable)
      --common              Scan only common ports (top 100 most used ports)
      --no-banner           Don't display the tool banner

    EXAMPLES:
      Basic scan:           python threatsight.py 192.168.1.1
      Common ports:         python threatsight.py example.com --common
      Stealth SYN scan:     python threatsight.py 192.168.1.1 --syn --stealth
      Custom port range:    python threatsight.py 10.0.0.1 -s 80 -e 443
      Async scanning:       python threatsight.py target.com -t async

    PERFORMANCE TIPS:
      - Use 'threaded' for general purpose scanning
      - Use 'process' for CPU-intensive tasks on multi-core systems
      - Use 'async' for high concurrency with many ports
      - Use 'benchmark' to test different scanning methods

    SECURITY NOTES:
      - SYN scanning requires elevated privileges
      - Always ensure you have permission to scan targets
      - Stealth mode reduces scan speed but increases evasion
      - Respect network policies and legal boundaries

    For more information, visit: https://github.com/yourusername/threatsight
    """
    
    print(textwrap.dedent(help_text).strip())

def interactive_help():
    """Interactive help prompt"""
    while True:
        try:
            user_input = input("\nThreatSight Help - Type 'options', 'examples', 'exit', or '-h' for help: ").strip().lower()
            
            if user_input in ['exit', 'quit', 'q']:
                print("Exiting help system...")
                break
            elif user_input in ['options', 'o']:
                print("\nAVAILABLE OPTIONS:")
                print("  target              - Target IP or domain")
                print("  -s, --start PORT    - Start port (default: 1)")
                print("  -e, --end PORT      - End port (default: 1024)")
                print("  -t, --type TYPE     - Scanning type (threaded|process|async|benchmark)")
                print("  --syn               - Use SYN scan (requires root)")
                print("  --stealth           - Enable stealth mode")
                print("  --common            - Scan common ports only")
                print("  --no-banner         - Hide banner")
                
            elif user_input in ['examples', 'ex', 'e']:
                print("\nEXAMPLES:")
                print("  python threatsight.py 192.168.1.1")
                print("  python threatsight.py example.com --common --stealth")
                print("  python threatsight.py 10.0.0.1 -s 20 -e 1000 -t async")
                print("  python threatsight.py target.com --syn (requires root)")
                
            elif user_input in ['-h', 'help', 'h']:
                display_help()
                
            elif user_input == '':
                continue
                
            else:
                print("Unknown command. Type 'options', 'examples', or 'exit'")
                
        except KeyboardInterrupt:
            print("\nExiting help system...")
            break
        except EOFError:
            print("\nExiting help system...")
            break

# Argument parser setup
parser = argparse.ArgumentParser(description="ThreatSight - Advanced Network Reconnaissance Tool", 
                                add_help=False,  # Disable default help to use custom one
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=textwrap.dedent("""
                                Examples:
                                  Basic scan:        python threatsight.py 192.168.1.1
                                  Common ports:      python threatsight.py example.com --common
                                  Stealth scan:      python threatsight.py target.com --stealth
                                
                                Type 'python threatsight.py -h' for detailed help.
                                """))

parser.add_argument("target", nargs="?", help="Target IP or domain")
parser.add_argument("-s", "--start", type=int, default=1, help="Start port (default: 1)")
parser.add_argument("-e", "--end", type=int, default=1024, help="End port (default: 1024)")
parser.add_argument("-t", "--type", choices=["threaded", "process", "async", "benchmark"], 
                   default="threaded", help="Scanning approach (default: threaded)")
parser.add_argument("--syn", action="store_true", help="Use SYN scan instead of TCP connect")
parser.add_argument("--stealth", action="store_true", help="Enable stealth mode")
parser.add_argument("--common", action="store_true", help="Scan only common ports")
parser.add_argument("--no-banner", action="store_true", help="Don't display the banner")
parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")

# Parse arguments
args = parser.parse_args()


# Common ports and their services
COMMON_PORTS = {
    7: {"name": "Echo", "description": "Echo service", "protocol": "TCP/UDP"},
    19: {"name": "CHARGEN", "description": "Character Generator Protocol", "protocol": "TCP/UDP"},
    20: {"name": "FTP-data", "description": "File Transfer Protocol data transfer", "protocol": "TCP"},
    21: {"name": "FTP", "description": "File Transfer Protocol command control", "protocol": "TCP/UDP"},
    22: {"name": "SSH/SCP/SFTP", "description": "Secure Shell, secure logins, file transfers", "protocol": "TCP/UDP"},
    23: {"name": "Telnet", "description": "Telnet protocol for unencrypted text communications", "protocol": "TCP"},
    25: {"name": "SMTP", "description": "Simple Mail Transfer Protocol for email routing", "protocol": "TCP"},
    42: {"name": "WINS Replication", "description": "Microsoft Windows Internet Name Service", "protocol": "TCP/UDP"},
    43: {"name": "WHOIS", "description": "Whois service for domain information", "protocol": "TCP/UDP"},
    49: {"name": "TACACS", "description": "Terminal Access Controller Access-Control System", "protocol": "UDP"},
    53: {"name": "DNS", "description": "Domain Name System name resolver", "protocol": "TCP/UDP"},
    67: {"name": "DHCP/BOOTP Server", "description": "Dynamic Host Configuration Protocol server", "protocol": "UDP"},
    68: {"name": "DHCP/BOOTP Client", "description": "Dynamic Host Configuration Protocol client", "protocol": "UDP"},
    69: {"name": "TFTP", "description": "Trivial File Transfer Protocol", "protocol": "UDP"},
    70: {"name": "Gopher", "description": "Document distribution protocol", "protocol": "TCP"},
    79: {"name": "Finger", "description": "User information protocol", "protocol": "TCP"},
    80: {"name": "HTTP", "description": "Hypertext Transfer Protocol", "protocol": "TCP/UDP"},
    88: {"name": "Kerberos", "description": "Network authentication system", "protocol": "TCP/UDP"},
    102: {"name": "Microsoft Exchange ISO-TSAP", "description": "Microsoft Exchange ISO Transport Service", "protocol": "TCP"},
    110: {"name": "POP3", "description": "Post Office Protocol version 3", "protocol": "TCP"},
    113: {"name": "Ident", "description": "Identification Protocol", "protocol": "TCP"},
    119: {"name": "NNTP", "description": "Network News Transfer Protocol", "protocol": "TCP"},
    123: {"name": "NTP", "description": "Network Time Protocol", "protocol": "UDP"},
    135: {"name": "Microsoft RPC EPMAP", "description": "Microsoft Remote Procedure Call", "protocol": "TCP/UDP"},
    137: {"name": "NetBIOS-ns", "description": "NetBIOS Name Service", "protocol": "TCP/UDP"},
    138: {"name": "NetBIOS-dgm", "description": "NetBIOS Datagram Service", "protocol": "TCP/UDP"},
    139: {"name": "NetBIOS-ssn", "description": "NetBIOS Session Service", "protocol": "TCP/UDP"},
    143: {"name": "IMAP", "description": "Internet Message Access Protocol", "protocol": "TCP/UDP"},
    161: {"name": "SNMP-agents", "description": "Simple Network Management Protocol agents", "protocol": "UDP"},
    162: {"name": "SNMP-trap", "description": "Simple Network Management Protocol traps", "protocol": "UDP"},
    177: {"name": "XDMCP", "description": "X Display Manager Control Protocol", "protocol": "UDP"},
    179: {"name": "BGP", "description": "Border Gateway Protocol", "protocol": "TCP"},
    194: {"name": "IRC", "description": "Internet Relay Chat", "protocol": "UDP"},
    201: {"name": "AppleTalk", "description": "AppleTalk Routing Maintenance", "protocol": "TCP/UDP"},
    264: {"name": "BGMP", "description": "Border Gateway Multicast Protocol", "protocol": "TCP/UDP"},
    318: {"name": "TSP", "description": "Time Stamp Protocol", "protocol": "TCP/UDP"},
    381: {"name": "HP Openview", "description": "HP performance data collector", "protocol": "TCP/UDP"},
    383: {"name": "HP Openview", "description": "HP data alarm manager", "protocol": "TCP/UDP"},
    389: {"name": "LDAP", "description": "Lightweight Directory Access Protocol", "protocol": "TCP/UDP"},
    411: {"name": "Direct Connect Hub", "description": "Remote MT Protocol", "protocol": "TCP/UDP"},
    412: {"name": "Direct Connect Client", "description": "Trap Convention Port", "protocol": "TCP/UDP"},
    427: {"name": "SLP", "description": "Service Location Protocol", "protocol": "TCP"},
    443: {"name": "HTTPS", "description": "HTTP Secure over SSL/TLS", "protocol": "TCP/UDP"},
    445: {"name": "Microsoft DS SMB", "description": "Microsoft Directory Services and SMB file-sharing", "protocol": "TCP/UDP"},
    464: {"name": "Kerberos", "description": "Kerberos password settings", "protocol": "TCP/UDP"},
    465: {"name": "SMTPS", "description": "SMTP over TLS/SSL", "protocol": "TCP"},
    497: {"name": "Dantz Retrospect", "description": "Backup software suite", "protocol": "TCP/UDP"},
    500: {"name": "IPSec/ISAKMP/IKE", "description": "Internet Protocol Security", "protocol": "UDP"},
    512: {"name": "rexec", "description": "Remote Process Execution", "protocol": "TCP"},
    513: {"name": "rlogin", "description": "Remote login", "protocol": "TCP"},
    514: {"name": "syslog", "description": "Syslog Protocol", "protocol": "UDP"},
    515: {"name": "LPD/LPR", "description": "Line Printer Daemon/Remote protocol", "protocol": "TCP"},
    520: {"name": "RIP", "description": "Routing Information Protocol", "protocol": "UDP"},
    521: {"name": "RIPng", "description": "RIP for IPv6", "protocol": "UDP"},
    540: {"name": "UUCP", "description": "Unix-to-Unix Copy Protocol", "protocol": "TCP"},
    546: {"name": "DHCPv6 Client", "description": "DHCP version 6 client", "protocol": "UDP"},
    547: {"name": "DHCPv6 Server", "description": "DHCP version 6 server", "protocol": "UDP"},
    548: {"name": "AFP", "description": "Apple Filing Protocol", "protocol": "TCP"},
    554: {"name": "RTSP", "description": "Real Time Streaming Protocol", "protocol": "TCP/UDP"},
    560: {"name": "rmonitor", "description": "Remote Monitor", "protocol": "UDP"},
    563: {"name": "NNTPS", "description": "NNTP over TLS/SSL", "protocol": "TCP/UDP"},
    587: {"name": "SMTP", "description": "Email message submission", "protocol": "TCP"},
    591: {"name": "FileMaker", "description": "FileMaker Web Companion", "protocol": "TCP"},
    593: {"name": "Microsoft DCOM", "description": "Distributed Component Object Model", "protocol": "TCP/UDP"},
    596: {"name": "SMSD", "description": "SysMan Station daemon", "protocol": "TCP/UDP"},
    631: {"name": "IPP", "description": "Internet Printing Protocol", "protocol": "TCP"},
    636: {"name": "LDAPS", "description": "LDAP over TLS/SSL", "protocol": "TCP/UDP"},
    639: {"name": "MSDP", "description": "Multicast Source Discovery Protocol", "protocol": "TCP"},
    646: {"name": "LDP", "description": "Label Distribution Protocol for MPLS", "protocol": "TCP/UDP"},
    691: {"name": "Microsoft Exchange", "description": "Microsoft Exchange Routing", "protocol": "TCP"},
    860: {"name": "iSCSI", "description": "Internet Small Computer Systems Interface", "protocol": "TCP"},
    873: {"name": "rsync", "description": "File synchronization protocol", "protocol": "TCP"},
    902: {"name": "VMware Server", "description": "VMware ESXi hypervisor", "protocol": "TCP/UDP"},
    989: {"name": "FTPS-data", "description": "FTP data over TLS/SSL", "protocol": "TCP"},
    990: {"name": "FTPS", "description": "FTP control over TLS/SSL", "protocol": "TCP"},
    993: {"name": "IMAPS", "description": "IMAP over SSL", "protocol": "TCP"},
    995: {"name": "POP3S", "description": "POP3 over SSL", "protocol": "TCP/UDP"},
    1025: {"name": "Microsoft RPC", "description": "Microsoft Remote Procedure Call", "protocol": "TCP"},
    1080: {"name": "SOCKS", "description": "SOCKS proxy", "protocol": "TCP/UDP"},
    1194: {"name": "OpenVPN", "description": "OpenVPN", "protocol": "TCP/UDP"},
    1214: {"name": "KAZAA", "description": "Peer-to-peer file-sharing", "protocol": "TCP"},
    1241: {"name": "Nessus", "description": "Nessus Security Scanner", "protocol": "TCP/UDP"},
    1311: {"name": "Dell OpenManage", "description": "Dell EMC OpenManage Server Administrator", "protocol": "TCP"},
    1337: {"name": "WASTE", "description": "Encrypted file-sharing program", "protocol": "TCP"},
    1589: {"name": "Cisco VQP", "description": "Cisco VLAN Query Protocol", "protocol": "TCP/UDP"},
    1701: {"name": "L2TP", "description": "Layer Two Tunneling Protocol VPN", "protocol": "TCP"},
    1720: {"name": "H.323", "description": "H.323 Call Control Signaling", "protocol": "TCP"},
    1723: {"name": "PPTP", "description": "Point-to-Point Tunneling Protocol VPN", "protocol": "TCP/UDP"},
    1725: {"name": "Steam", "description": "Valve Steam Client", "protocol": "UDP"},
    1741: {"name": "CiscoWorks SNMS", "description": "CiscoWorks Small Network Management Solution", "protocol": "TCP"},
    1755: {"name": "MMS", "description": "Microsoft Media Server", "protocol": "TCP/UDP"},
    1812: {"name": "RADIUS", "description": "RADIUS authentication", "protocol": "UDP"},
    1813: {"name": "RADIUS", "description": "RADIUS accounting", "protocol": "UDP"},
    1863: {"name": "MSN Messenger", "description": "MSN Messenger, Xbox Live", "protocol": "TCP/UDP"},
    1900: {"name": "UPnP", "description": "Universal Plug and Play", "protocol": "UDP"},
    1985: {"name": "HSRP", "description": "Cisco Hot Standby Router Protocol", "protocol": "UDP"},
    2000: {"name": "Cisco SCCP", "description": "Skinny Client Control Protocol", "protocol": "TCP"},
    2002: {"name": "Cisco ACS", "description": "Cisco Access Control Server", "protocol": "TCP"},
    2049: {"name": "NFS", "description": "Network File Sharing", "protocol": "UDP"},
    2082: {"name": "cPanel", "description": "cPanel default", "protocol": "TCP/UDP"},
    2083: {"name": "cPanel SSL", "description": "cPanel default SSL", "protocol": "TCP/UDP"},
    2100: {"name": "amiganetfs", "description": "Amiga Network Filesystem", "protocol": "TCP"},
    2222: {"name": "DirectAdmin", "description": "Web hosting control panel", "protocol": "TCP"},
    2302: {"name": "HALO", "description": "HALO game", "protocol": "UDP"},
    2483: {"name": "Oracle", "description": "Oracle database insecure connections", "protocol": "TCP/UDP"},
    2484: {"name": "Oracle SSL", "description": "Oracle database SSL connections", "protocol": "TCP/UDP"},
    2745: {"name": "Bagle", "description": "Bagle computer worm", "protocol": "TCP"},
    2967: {"name": "Symantec AV", "description": "Symantec System Center agent", "protocol": "TCP/UDP"},
    3050: {"name": "Interbase", "description": "Borland Interbase database", "protocol": "TCP/UDP"},
    3074: {"name": "XBOX Live", "description": "Xbox LIVE and Games for Windows", "protocol": "TCP/UDP"},
    3127: {"name": "MyDoom", "description": "MyDoom computer worm", "protocol": "TCP"},
    3128: {"name": "HTTP Proxy", "description": "Common web proxy server", "protocol": "TCP"},
    3222: {"name": "GLBP", "description": "Gateway Load Balancing Protocol", "protocol": "TCP/UDP"},
    3260: {"name": "iSCSI Target", "description": "Microsoft iSCSI Target Server", "protocol": "TCP/UDP"},
    3306: {"name": "MySQL", "description": "MySQL database system", "protocol": "TCP"},
    3389: {"name": "RDP", "description": "Remote Desktop Protocol", "protocol": "TCP"},
    3689: {"name": "DAAP", "description": "Digital Audio Access Protocol", "protocol": "TCP"},
    3690: {"name": "SVN", "description": "Apache Subversion version control", "protocol": "TCP/UDP"},
    3724: {"name": "World of Warcraft", "description": "Blizzard games", "protocol": "TCP/UDP"},
    3784: {"name": "Ventrilo", "description": "Ventrilo VoIP program", "protocol": "TCP/UDP"},
    3785: {"name": "Ventrilo", "description": "Ventrilo VoIP program", "protocol": "TCP/UDP"},
    4333: {"name": "mSQL", "description": "Mini SQL server", "protocol": "TCP"},
    4444: {"name": "Blaster", "description": "Blaster computer worm", "protocol": "TCP/UDP"},
    4500: {"name": "IPSec NAT-T", "description": "IPSec NAT Traversal", "protocol": "UDP"},
    4664: {"name": "Google Desktop", "description": "Google Desktop HTTP server", "protocol": "TCP"},
    4672: {"name": "eMule", "description": "Peer-to-peer file-sharing", "protocol": "UDP"},
    4899: {"name": "Radmin", "description": "Remote computer control software", "protocol": "TCP"},
    5000: {"name": "UPnP", "description": "Universal Plug and Play", "protocol": "TCP"},
    5001: {"name": "iperf", "description": "Bandwidth measurement tool", "protocol": "TCP"},
    5004: {"name": "RTP", "description": "Real-time Transport Protocol", "protocol": "UDP"},
    5005: {"name": "RTP", "description": "Real-time Transport Protocol", "protocol": "UDP"},
    5050: {"name": "Yahoo! Messenger", "description": "Yahoo Instant messaging", "protocol": "TCP"},
    5060: {"name": "SIP", "description": "Session Initiation Protocol", "protocol": "TCP/UDP"},
    5061: {"name": "SIP-TLS", "description": "SIP over TLS", "protocol": "TCP"},
    5190: {"name": "AIM/ICQ", "description": "AOL Instant Messenger, ICQ", "protocol": "TCP/UDP"},
    5222: {"name": "XMPP", "description": "Extensible Messaging and Presence Protocol", "protocol": "TCP/UDP"},
    5223: {"name": "XMPP", "description": "Extensible Messaging and Presence Protocol", "protocol": "TCP/UDP"},
    5353: {"name": "mDNS", "description": "Multicast DNS", "protocol": "UDP"},
    5432: {"name": "PostgreSQL", "description": "PostgreSQL database system", "protocol": "TCP"},
    5554: {"name": "Sasser", "description": "Sasser computer worm", "protocol": "TCP"},
    5631: {"name": "pcAnywhere", "description": "Symantec pcAnywhere", "protocol": "UDP"},
    5632: {"name": "pcAnywhere", "description": "Symantec pcAnywhere", "protocol": "UDP"},
    5800: {"name": "VNC HTTP", "description": "VNC over HTTP", "protocol": "TCP"},
    5900: {"name": "VNC", "description": "Virtual Network Computing", "protocol": "TCP/UDP"},
    6000: {"name": "X11", "description": "X Window System", "protocol": "TCP"},
    6001: {"name": "X11", "description": "X Window System", "protocol": "UDP"},
    6112: {"name": "Diablo", "description": "Diablo game", "protocol": "TCP/UDP"},
    6129: {"name": "DameWare", "description": "Remote access software", "protocol": "TCP"},
    6257: {"name": "WinMX", "description": "Windows Music Exchange", "protocol": "UDP"},
    6346: {"name": "Gnutella", "description": "Gnutella2 peer-to-peer", "protocol": "TCP/UDP"},
    6347: {"name": "Gnutella", "description": "Gnutella2 peer-to-peer", "protocol": "TCP/UDP"},
    6379: {"name": "Redis", "description": "Redis database", "protocol": "TCP"},
    6500: {"name": "GameSpy", "description": "GameSpy gaming", "protocol": "TCP/UDP"},
    6566: {"name": "SANE", "description": "Scanner Access Now Easy", "protocol": "TCP/UDP"},
    6588: {"name": "AnalogX", "description": "AnalogX proxy server", "protocol": "TCP"},
    6665: {"name": "IRC", "description": "Internet Relay Chat", "protocol": "TCP"},
    6666: {"name": "IRC", "description": "Internet Relay Chat", "protocol": "TCP"},
    6667: {"name": "IRC", "description": "Internet Relay Chat", "protocol": "TCP"},
    6668: {"name": "IRC", "description": "Internet Relay Chat", "protocol": "TCP"},
    6669: {"name": "IRC", "description": "Internet Relay Chat", "protocol": "TCP"},
    6679: {"name": "IRC SSL", "description": "IRC over SSL", "protocol": "TCP"},
    6697: {"name": "IRC SSL", "description": "IRC over SSL", "protocol": "TCP"},
    6699: {"name": "Napster", "description": "Napster file-sharing", "protocol": "TCP"},
    6881: {"name": "BitTorrent", "description": "BitTorrent peer-to-peer", "protocol": "TCP/UDP"},
    6891: {"name": "Windows Live", "description": "Windows Live Messenger", "protocol": "TCP/UDP"},
    6901: {"name": "Windows Live", "description": "Windows Live Messenger", "protocol": "TCP/UDP"},
    6970: {"name": "QuickTime", "description": "QuickTime streaming", "protocol": "TCP/UDP"},
    7000: {"name": "Cassandra", "description": "Apache Cassandra inter-node", "protocol": "TCP"},
    7001: {"name": "Cassandra SSL", "description": "Apache Cassandra SSL inter-node", "protocol": "TCP"},
    7199: {"name": "Cassandra JMX", "description": "Apache Cassandra JMX", "protocol": "TCP"},
    7648: {"name": "CU-SeeMe", "description": "CU-SeeMe video conferencing", "protocol": "TCP/UDP"},
    7649: {"name": "CU-SeeMe", "description": "CU-SeeMe video conferencing", "protocol": "TCP/UDP"},
    8000: {"name": "HTTP Alt", "description": "Alternative HTTP port", "protocol": "TCP"},
    8080: {"name": "HTTP Proxy", "description": "Common web proxy server", "protocol": "TCP"},
    8086: {"name": "Kaspersky", "description": "Kaspersky AV Control Center", "protocol": "TCP"},
    8087: {"name": "Kaspersky", "description": "Kaspersky AV Control Center", "protocol": "UDP"},
    8118: {"name": "Privoxy", "description": "Advertisement-filtering proxy", "protocol": "TCP"},
    8200: {"name": "VMware", "description": "VMware vSphere Fault Tolerance", "protocol": "TCP/UDP"},
    8222: {"name": "VMware", "description": "VMware Server Management", "protocol": "TCP/UDP"},
    8500: {"name": "ColdFusion", "description": "Adobe ColdFusion", "protocol": "TCP/UDP"},
    8767: {"name": "Teamspeak", "description": "VoIP for gaming", "protocol": "UDP"},
    8866: {"name": "Bagle.B", "description": "Bagle.B computer worm", "protocol": "TCP"},
    9042: {"name": "Cassandra", "description": "Apache Cassandra client", "protocol": "TCP"},
    9100: {"name": "PDL", "description": "PDL Data Stream for printing", "protocol": "TCP"},
    9101: {"name": "Bacula", "description": "Bacula backup", "protocol": "TCP/UDP"},
    9102: {"name": "Bacula", "description": "Bacula backup", "protocol": "TCP/UDP"},
    9103: {"name": "Bacula", "description": "Bacula backup", "protocol": "TCP/UDP"},
    9119: {"name": "MXit", "description": "MXit Instant Messaging", "protocol": "TCP/UDP"},
    9800: {"name": "WebDAV", "description": "Web-based Distributed Authoring", "protocol": "TCP/UDP"},
    9898: {"name": "Dabber", "description": "Dabber computer worm", "protocol": "TCP"},
    9999: {"name": "Urchin", "description": "Urchin Web Analytics", "protocol": "TCP/UDP"},
    10000: {"name": "Webmin", "description": "Webmin system administration", "protocol": "TCP/UDP"},
    10161: {"name": "SNMP SSL", "description": "SNMP agents encrypted", "protocol": "TCP"},
    10162: {"name": "SNMP SSL", "description": "SNMP traps encrypted", "protocol": "TCP"},
    10113: {"name": "NetIQ", "description": "NetIQ Endpoint", "protocol": "TCP/UDP"},
    10114: {"name": "NetIQ", "description": "NetIQ Qcheck", "protocol": "TCP/UDP"},
    10115: {"name": "NetIQ", "description": "NetIQ Endpoint", "protocol": "TCP/UDP"},
    10116: {"name": "NetIQ", "description": "NetIQ VoIP Assessor", "protocol": "TCP/UDP"},
    11371: {"name": "OpenPGP", "description": "OpenPGP HTTP Keyserver", "protocol": "TCP/UDP"},
    12345: {"name": "NetBus", "description": "NetBus Trojan horse", "protocol": "TCP"},
    13720: {"name": "NetBackup", "description": "NetBackup request daemon", "protocol": "TCP/UDP"},
    13721: {"name": "NetBackup", "description": "NetBackup request daemon", "protocol": "TCP/UDP"},
    14567: {"name": "Battlefield", "description": "Battlefield game", "protocol": "UDP"},
    15118: {"name": "Dipnet", "description": "Dipnet/Oddbob Trojan", "protocol": "TCP"},
    19226: {"name": "AdminSecure", "description": "Panda Software AdminSecure", "protocol": "TCP"},
    19638: {"name": "Ensim", "description": "Ensim Control Panel", "protocol": "TCP"},
    20000: {"name": "Usermin", "description": "Web email interface", "protocol": "TCP/UDP"},
    24800: {"name": "Synergy", "description": "Keyboard/mouse sharing", "protocol": "TCP/UDP"},
    25999: {"name": "Xfire", "description": "Xfire gaming communication", "protocol": "TCP"},
    27015: {"name": "Half-Life", "description": "Half-Life game", "protocol": "UDP"},
    27017: {"name": "MongoDB", "description": "MongoDB database", "protocol": "TCP"},
    27374: {"name": "Sub7", "description": "Sub7 Trojan horse", "protocol": "TCP/UDP"},
    28960: {"name": "Call of Duty", "description": "Call of Duty game", "protocol": "TCP/UDP"},
    31337: {"name": "Back Orifice", "description": "Back Orifice Trojan", "protocol": "TCP/UDP"},
    33434: {"name": "traceroute", "description": "Traceroute utility", "protocol": "UDP"},
    3389: {"name": "RDP", "description": "Remote Desktop Protocol", "protocol": "TCP"},
    5060: {"name": "SIP", "description": "Session Initiation Protocol", "protocol": "TCP/UDP"},
    5061: {"name": "SIP-TLS", "description": "SIP over TLS", "protocol": "TCP"},
}

@dataclass
class ScanResult:
    port: int
    is_open: bool
    response_time: float
    scan_type: str
    service_info: Optional[Dict] = None

class SYNPacket:
    """Class to create and send SYN packets for stealth scanning"""
    def __init__(self, src_ip: str, dest_ip: str, dest_port: int):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.src_port = random.randint(1024, 65535)
        self.seq_num = random.randint(0, 4294967295)
        
    def create_packet(self) -> bytes:
        """Create a SYN packet"""
        # IP header
        ip_ver_ihl = 0x45  # Version 4, IHL 5 (20 bytes)
        ip_tos = 0         # Type of service
        ip_total_len = 40  # Total length (IP header + TCP header)
        ip_id = random.randint(0, 65535)  # Identification
        ip_frag_off = 0    # Fragment offset
        ip_ttl = 64        # Time to live
        ip_proto = socket.IPPROTO_TCP  # Protocol (TCP)
        ip_check = 0       # Checksum (will calculate later)
        
        # Convert IP addresses to binary form
        src_addr = socket.inet_aton(self.src_ip)
        dst_addr = socket.inet_aton(self.dest_ip)
        
        # IP header (without checksum)
        ip_header_no_chk = struct.pack('!BBHHHBB',
                                     ip_ver_ihl, ip_tos, ip_total_len,
                                     ip_id, ip_frag_off,
                                     ip_ttl, ip_proto) + struct.pack('H', ip_check) + src_addr + dst_addr
        
        # Calculate IP checksum
        ip_check = self.calculate_checksum(ip_header_no_chk)
        
        # Final IP header
        ip_header = struct.pack('!BBHHHBB',
                              ip_ver_ihl, ip_tos, ip_total_len,
                              ip_id, ip_frag_off,
                              ip_ttl, ip_proto) + struct.pack('H', ip_check) + src_addr + dst_addr
        
        # TCP header
        tcp_src = self.src_port      # Source port
        tcp_dst = self.dest_port     # Destination port
        tcp_seq = self.seq_num       # Sequence number
        tcp_ack = 0                  # Acknowledgement number
        tcp_offset = 5 << 4          # Data offset (5 words = 20 bytes)
        tcp_flags = 0x02             # SYN flag
        tcp_window = socket.htons(5840)  # Window size
        tcp_check = 0                # Checksum
        tcp_urg_ptr = 0              # Urgent pointer
        
        # TCP pseudo header for checksum calculation
        pseudo_header = struct.pack('!4s4sBBH',
                                  socket.inet_aton(self.src_ip),
                                  socket.inet_aton(self.dest_ip),
                                  0, socket.IPPROTO_TCP, 20)
        
        # TCP header (without checksum)
        tcp_header_no_chk = struct.pack('!HHLLBBHHH',
                                      tcp_src, tcp_dst,
                                      tcp_seq, tcp_ack,
                                      tcp_offset, tcp_flags, tcp_window,
                                      tcp_check, tcp_urg_ptr)
        
        # Calculate TCP checksum
        tcp_check = self.calculate_checksum(pseudo_header + tcp_header_no_chk)
        
        # Final TCP header
        tcp_header = struct.pack('!HHLLBBHHH',
                               tcp_src, tcp_dst,
                               tcp_seq, tcp_ack,
                               tcp_offset, tcp_flags, tcp_window,
                               tcp_check, tcp_urg_ptr)
        
        return ip_header + tcp_header
    
    def calculate_checksum(self, data: bytes) -> int:
        """Calculate checksum for the given data"""
        if len(data) % 2:
            data += b'\x00'
        
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        
        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s



class ThreatSightScanner:
    def __init__(self, target_ip: str, stealth_mode: bool = False):
        self.target_ip = target_ip
        self.stealth_mode = stealth_mode
        self.scan_results = []
        self.scan_times = []
        
    def print_banner(self):
        """Print the ThreatSight banner"""
        print(THREATSIGHT_BANNER)
        print(f"{Fore.CYAN}Target: {Fore.WHITE}{self.target_ip}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Started: {Fore.WHITE}{time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print("-" * 80)
        
    def get_target(self):
        """Get and validate target IP/domain"""
        while True:
            target = input("Enter the Target IP or Domain: ").strip()
            parts = target.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return target
            
            try:
                ip = socket.gethostbyname(target)
                print(f"Resolved {target} to {ip}")
                return ip
            except socket.gaierror:
                print(f"Invalid IP address or Domain format. Try again")

    def get_service_info(self, port: int) -> Optional[Dict]:
        """Get service information for a port if it's a common port"""
        return COMMON_PORTS.get(port)

    def tcp_connect_scan(self, port: int) -> ScanResult:
        """Traditional TCP connect scan"""
        start_time = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((self.target_ip, port))
                response_time = time.time() - start_time
                
                if self.stealth_mode:
                    time.sleep(random.uniform(0.1, 0.5))  # Random delay for stealth
                
                service_info = self.get_service_info(port)
                return ScanResult(port, result == 0, response_time, "TCP", service_info)
        except:
            service_info = self.get_service_info(port)
            return ScanResult(port, False, time.time() - start_time, "TCP", service_info)


#scanning using TCP_SYN
    def syn_scan(self, port: int) -> ScanResult:
        """SYN scan implementation"""
        start_time = time.time()
        
        try:
            # Create raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.settimeout(1)
            
            # Generate source IP (random for stealth mode)
            src_ip = self.generate_random_ip() if self.stealth_mode else socket.gethostbyname(socket.gethostname())
            
            # Create and send SYN packet
            syn_packet = SYNPacket(src_ip, self.target_ip, port)
            packet = syn_packet.create_packet()
            s.sendto(packet, (self.target_ip, 0))
            
            # Listen for response
            response = s.recvfrom(1024)[0]
            
            # Parse response
            ip_header = response[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            
            tcp_header = response[iph_length:iph_length+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            
            dest_port = tcph[1]
            flags = tcph[5]
            
            # Check if this is a response to our SYN packet
            if dest_port == syn_packet.src_port:
                # Check for SYN-ACK (open port)
                if flags & 0x12 == 0x12:  # SYN and ACK flags set
                    response_time = time.time() - start_time
                    
                    if self.stealth_mode:
                        time.sleep(random.uniform(0.1, 0.5))
                    
                    service_info = self.get_service_info(port)
                    s.close()
                    return ScanResult(port, True, response_time, "SYN", service_info)
                
                # Check for RST (closed port)
                elif flags & 0x04 == 0x04:  # RST flag set
                    response_time = time.time() - start_time
                    service_info = self.get_service_info(port)
                    s.close()
                    return ScanResult(port, False, response_time, "SYN", service_info)
            
            s.close()
            service_info = self.get_service_info(port)
            return ScanResult(port, False, time.time() - start_time, "SYN", service_info)
            
        except socket.timeout:
            # No response (filtered port)
            service_info = self.get_service_info(port)
            return ScanResult(port, False, time.time() - start_time, "SYN", service_info)
        except PermissionError:
            print(f"{Fore.RED}Permission denied for SYN scan. Need root privileges.{Style.RESET_ALL}")
            # Fall back to TCP connect scan
            return self.tcp_connect_scan(port)
        except Exception as e:
            # Other errors, fall back to TCP connect
            return self.tcp_connect_scan(port)

    async def async_tcp_scan(self, port: int) -> ScanResult:
        """Asynchronous TCP scan"""
        loop = asyncio.get_event_loop()
        try:
            start_time = time.time()
            # Create connection with timeout
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_ip, port),
                    timeout=1.0
                )
                writer.close()
                await writer.wait_closed()
                response_time = time.time() - start_time
                
                if self.stealth_mode:
                    await asyncio.sleep(random.uniform(0.1, 0.5))
                
                service_info = self.get_service_info(port)
                return ScanResult(port, True, response_time, "Async-TCP", service_info)
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                service_info = self.get_service_info(port)
                return ScanResult(port, False, time.time() - start_time, "Async-TCP", service_info)
        except Exception:
            service_info = self.get_service_info(port)
            return ScanResult(port, False, time.time() - start_time, "Async-TCP", service_info)

    def threaded_scan(self, start_port: int, end_port: int, max_threads: int = 100, scan_type: str = "tcp") -> List[ScanResult]:
        """Multithreaded scanning approach"""
        open_ports = []
        ports = range(start_port, end_port + 1)
        
        # Choose the appropriate scan function
        scan_func = self.syn_scan if scan_type == "syn" else self.tcp_connect_scan

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(scan_func, port): port for port in ports}
            
            for future in tqdm(as_completed(futures), total=len(ports), 
                              desc=f"{Fore.CYAN}ThreatSight {scan_type.upper()} Scanning{Style.RESET_ALL}",
                              bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.CYAN, Style.RESET_ALL)):
                result = future.result()
                if result.is_open:
                    open_ports.append(result)
                    self.print_port_info(result)

        return open_ports

    def print_port_info(self, result: ScanResult):
        """Print information about an open port"""
        if result.service_info:
            service = result.service_info
            print(f"{Fore.GREEN}[+] Port {result.port}/tcp open {service['name']} - {service['description']} ({service['protocol']}){Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] Port {result.port}/tcp open (Unknown service){Style.RESET_ALL}")

    def process_scan(self, start_port: int, end_port: int, max_processes: int = 4, scan_type: str = "tcp") -> List[ScanResult]:
        """Multiprocessing scanning approach"""
        open_ports = []
        ports = range(start_port, end_port + 1)
        
        # Split ports into chunks for each process
        chunk_size = len(ports) // max_processes
        port_chunks = [ports[i:i + chunk_size] for i in range(0, len(ports), chunk_size)]
        
        with ProcessPoolExecutor(max_workers=max_processes) as executor:
            futures = {executor.submit(self._process_scan_chunk, chunk, scan_type): chunk for chunk in port_chunks}
            
            for future in tqdm(as_completed(futures), total=len(port_chunks), 
                              desc=f"{Fore.CYAN}ThreatSight {scan_type.upper()} Processing{Style.RESET_ALL}",
                              bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.CYAN, Style.RESET_ALL)):
                open_ports.extend(future.result())
        
        return open_ports

    def _process_scan_chunk(self, ports: List[int], scan_type: str) -> List[ScanResult]:
        """Helper method for process-based scanning"""
        results = []
        scan_func = self.syn_scan if scan_type == "syn" else self.tcp_connect_scan
        
        for port in ports:
            result = scan_func(port)
            if result.is_open:
                results.append(result)
                self.print_port_info(result)
        return results

    async def async_scan(self, start_port: int, end_port: int, max_concurrent: int = 100) -> List[ScanResult]:
        """Asynchronous scanning approach"""
        open_ports = []
        ports = range(start_port, end_port + 1)
        
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def limited_scan(port):
            async with semaphore:
                return await self.async_tcp_scan(port)
        
        tasks = [limited_scan(port) for port in ports]
        
        for task in tqdm(asyncio.as_completed(tasks), total=len(tasks), 
                        desc=f"{Fore.CYAN}ThreatSight Async Scanning{Style.RESET_ALL}",
                        bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.CYAN, Style.RESET_ALL)):
            result = await task
            if result.is_open:
                open_ports.append(result)
                self.print_port_info(result)
        
        return open_ports

    def benchmark_scans(self, start_port: int, end_port: int) -> None:
        """Benchmark different scanning approaches"""
        approaches = [
            ("Threaded TCP", lambda: self.threaded_scan(start_port, end_port, scan_type="tcp")),
            ("Threaded SYN", lambda: self.threaded_scan(start_port, end_port, scan_type="syn")),
            ("Process TCP", lambda: self.process_scan(start_port, end_port, scan_type="tcp")),
            ("Process SYN", lambda: self.process_scan(start_port, end_port, scan_type="syn")),
            ("Async TCP", lambda: asyncio.run(self.async_scan(start_port, end_port)))
        ]
        
        print(f"\n{Fore.CYAN}=== ThreatSight Benchmarking Scan Approaches ==={Style.RESET_ALL}")
        
        for name, scan_func in approaches:
            start_time = time.time()
            results = scan_func()
            end_time = time.time()
            
            self.scan_times.append((name, end_time - start_time, len(results)))
            
            print(f"{Fore.YELLOW}{name}: {end_time - start_time:.2f}s, {len(results)} open ports{Style.RESET_ALL}")

    def generate_random_ip(self) -> str:
        """Generate a random IP for stealth mode"""
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

    def run_scan(self, start_port: int, end_port: int, scan_type: str = "threaded", syn_scan: bool = False) -> List[ScanResult]:
        """Main method to run the selected scan type"""
        scan_method = "SYN" if syn_scan else "TCP"
        print(f"{Fore.CYAN}ThreatSight Starting {scan_type} {scan_method} scan on {self.target_ip}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Scanning ports: {start_port}-{end_port} ({end_port - start_port + 1} ports){Style.RESET_ALL}")
        
        start_time = time.time()
        
        if scan_type == "threaded":
            results = self.threaded_scan(start_port, end_port, scan_type="syn" if syn_scan else "tcp")
        elif scan_type == "process":
            results = self.process_scan(start_port, end_port, scan_type="syn" if syn_scan else "tcp")
        elif scan_type == "async":
            if syn_scan:
                print(f"{Fore.YELLOW}SYN scan not available for async mode, using TCP instead{Style.RESET_ALL}")
            results = asyncio.run(self.async_scan(start_port, end_port))
        elif scan_type == "benchmark":
            self.benchmark_scans(start_port, end_port)
            results = []
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")
        
        end_time = time.time()
        
        if results:
            print(f"\n{Fore.GREEN}ThreatSight Scan completed in {end_time - start_time:.2f} seconds{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Found {len(results)} open ports{Style.RESET_ALL}")
            
            # Print summary of common services found
            common_services = [r for r in results if r.service_info]
            if common_services:
                print(f"\n{Fore.CYAN}=== ThreatSight Common Services Found ==={Style.RESET_ALL}")
                for result in common_services:
                    service = result.service_info
                    print(f"  {Fore.YELLOW}Port {result.port}: {service['name']} - {service['description']}{Style.RESET_ALL}")
    


    from core.os_fingerprint import OSFingerprintDB  

    def enhanced_scan(self, ip: str, port: int):
        """Scan with OS fingerprinting"""
        # Get TCP response
        packet = self.send_probe(ip, port)
        
        # Detect OS
        os_info = OSFingerprintDB.detect_from_packet(packet)
        
        # Add to results
        return {
            "port": port,
            "state": "open",
            "service": self.detect_service(ip, port),
            "os_detected": os_info
        }


        return results
        


def main():
    parser = argparse.ArgumentParser(description="ThreatSight - Advanced Network Reconnaissance Tool", 
                                    add_help=False)
    parser.add_argument("target", nargs="?", help="Target IP or domain")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("-t", "--type", choices=["threaded", "process", "async", "benchmark"], 
                       default="threaded", help="Scanning approach (default: threaded)")
    parser.add_argument("--syn", action="store_true", help="Use SYN scan instead of TCP connect")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode")
    parser.add_argument("--common", action="store_true", help="Scan only common ports")
    parser.add_argument("--no-banner", action="store_true", help="Don't display the banner")
    parser.add_argument("-h", "--help", action="store_true", help="Show help message and exit")
    
    args = parser.parse_args()
    
    # Show help if requested or no arguments provided
    if args.help or (not args.target and len(sys.argv) == 1):
        scanner = ThreatSightScanner("", False)
        if not args.no_banner:
            scanner.print_banner()
        display_help()
        
        # Offer interactive help if no arguments were provided
        if len(sys.argv) == 1:
            response = input(f"\n{Fore.YELLOW}Would you like interactive help? (y/n): {Style.RESET_ALL}").strip().lower()
            if response in ['y', 'yes']:
                interactive_help()
        sys.exit(0)
    
    scanner = ThreatSightScanner("", args.stealth)
    
    if not args.no_banner:
        scanner.print_banner()
    
    if not args.target:
        target = scanner.get_target()
    else:
        target = args.target
    
    scanner.target_ip = target
    
    # Check if we need root for SYN scan
    if args.syn and os.geteuid() != 0:
        print(f"{Fore.RED}ThreatSight: SYN scan requires root privileges. Run with sudo.{Style.RESET_ALL}")
        sys.exit(1)
    
    # If common ports only, scan the well-known ports
    if args.common:
        common_ports = list(COMMON_PORTS.keys())
        common_ports.sort()
        start_port = min(common_ports)
        end_port = max(common_ports)
        print(f"{Fore.CYAN}ThreatSight: Scanning {len(common_ports)} common ports from {start_port} to {end_port}{Style.RESET_ALL}")
    else:
        start_port = args.start
        end_port = args.end
    
    try:
        scanner.run_scan(start_port, end_port, args.type, args.syn)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}ThreatSight: Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}ThreatSight: Error during scan: {e}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()


