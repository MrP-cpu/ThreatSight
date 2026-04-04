#!/usr/bin/env python3
"""ThreatSight CLI - Main Entry Point"""

import click
import sys
from pathlib import Path

# Add parent directory to path for development
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from threatsight.core.scanner import ThreatScanner
from threatsight.core.os_fingerprint import OSFingerprintDB
from threatsight.utils.helpers import print_banner

@click.group()
def cli():
    """ThreatSight - Advanced Network Vulnerability Scanner"""
    print_banner()

@cli.command()
@click.option('--target', '-t', required=True, help='Target IP or hostname')
@click.option('--ports', '-p', default='1-1024', help='Port range to scan')
@click.option('--scan-type', '-s', default='syn', type=click.Choice(['syn', 'udp', 'comprehensive']))
@click.option('--threads', '-T', default=10, help='Number of threads')
def scan(target, ports, scan_type, threads):
    """Perform network scan on target"""
    click.echo(f"Scanning {target} on ports {ports}")
    scanner = ThreatScanner()
    
    # Your existing scan logic here
    results = scanner.scan_target(target, ports, scan_type)
    
    # Add OS fingerprinting for comprehensive scans
    if scan_type == 'comprehensive':
        os_info = OSFingerprintDB.find_match(
            ttl=results.get('ttl', 64),
            window_size=results.get('window_size', 64240),
            df=results.get('df', True),
            options=results.get('tcp_options', [])
        )
        click.echo(f"OS Detection: {os_info['os']} ({os_info['final_confidence']}% confidence)")
    
    return results

@cli.command()
def version():
    """Show ThreatSight version"""
    from threatsight import __version__
    click.echo(f"ThreatSight version {__version__}")

if __name__ == "__main__":
    cli()
