"""ThreatSight - Advanced Network Vulnerability Scanner"""

__version__ = "2.0.0"
__author__ = "Parshant Kumar"
__license__ = "MIT"

from threatsight.core.os_fingerprint import OSFingerprintDB
from threatsight.core.scanner import ThreatScanner

__all__ = ["OSFingerprintDB", "ThreatScanner"]
