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


    # Implement OS detection using TTL, window size, and other TCP flags.
    # NEW: Develop a "smart" banner grabber that sends specific, service-aware requests (e.g., an HTTP GET request, an SSH protocol handshake, etc.).
    # NEW: Build a simple **plugin system** (e.g., loading Python modules as probes) to extend your scanner's functionality



class OSFingerprintDB:
    "DATABASE FOR OS FINGERPRINTS FOR DETECTION"
    OS_FINGERPRINTING = {
        {
            "os": "Linux (Kernel 4.x+)",
            "ttl": 64,
            "window_size": 29200,
            "df": True,
            "options": ["mss", "nop", "wscale", "nop", "nop", "ts"],
            "confidence": 85
        },
        {
            "os": "Linux (Kernel 2.4-2.6)",
            "ttl": 64,
            "window_size": 5840,
            "df": True,
            "options": ["mss", "nop", "wscale", "nop", "nop", "ts"],
            "confidence": 80
        },
        {
            "os": "Windows 10/11",
            "ttl": 128,
            "window_size": 64240,
            "df": True,
            "options": ["mss", "nop", "nop", "sack", "nop", "wscale"],
            "confidence": 90
        },
        {
            "os": "Windows 7/2008",
            "ttl": 128,
            "window_size": 8192,
            "df": True,
            "options": ["mss", "nop", "nop", "sack", "nop", "wscale"],
            "confidence": 85
        },
        {
            "os": "Windows XP",
            "ttl": 128,
            "window_size": 65535,
            "df": True,
            "options": ["mss", "nop", "nop", "sack"],
            "confidence": 80
        },
        {
            "os": "macOS (10.15+)",
            "ttl": 64,
            "window_size": 65535,
            "df": True,
            "options": ["mss", "nop", "wscale", "nop", "nop", "sack", "ts"],
            "confidence": 88
        },
        {
            "os": "FreeBSD",
            "ttl": 64,
            "window_size": 65535,
            "df": True,
            "options": ["mss", "nop", "wscale", "sack", "ts"],
            "confidence": 85
        },
        {
            "os": "Cisco IOS",
            "ttl": 255,
            "window_size": 4128,
            "df": True,
            "options": ["mss"],
            "confidence": 90
        },
        {
            "os": "Solaris",
            "ttl": 255,
            "window_size": 8760,
            "df": True,
            "options": ["mss", "nop", "wscale", "nop", "nop", "sack"],
            "confidence": 82
        }
        # Example additions based on your table
        {
            "os": "Solaris 2.5.1 - 2.8",
            "ttl": 255,  # From your ICMP entry
            "window_size": 8760, # Common Solaris window size
            "df": True,
            "options": ["mss", "nop", "wscale", "nop", "nop", "sack"], # Common options
            "confidence": 85  # High confidence due to unique TTL + window combo
        },
        {
            "os": "Windows 98",
            "ttl": 128,  # From your TCP entry
            "window_size": 8192, # A common Win9x/early NT window size
            "df": True,
            "options": ["mss", "nop", "nop", "sack"], # Simpler option list
            "confidence": 80
        },
        {
            "os": "FreeBSD 5",
            "ttl": 64,  # From your ICMP entry
            "window_size": 65535,
            "df": True,
            "options": ["mss", "nop", "wscale", "sack", "ts"],
            "confidence": 82
        }
    }

    
    @classmethod
    def find_match(cls, ttl: int, window_size: int, df: bool, options: list) -> dict:
        """Find the best OS match based on fingerprint characteristics.
        Returns a match with a calculated final_confidence."""
        best_match = None
        best_score = 0

        for fingerprint in cls.OS_FINGERPRINTS:
            score = 0
            # ... [same scoring logic as before] ...

            if score > best_score:
                best_score = score
                best_match = fingerprint.copy()
                best_match["match_score"] = score

        if best_match:
            # Refine the confidence: Blend the pre-defined confidence with the match accuracy.
            # Example 1: Simple multiplication (pre-defined confidence * % match)
            final_confidence = (best_match["confidence"] * (best_score / 100))

            # Example 2: Weighted average (e.g., 70% from match_score, 30% from pre-defined)
            # final_confidence = (best_score * 0.7) + (best_match["confidence"] * 0.3)

            best_match["final_confidence"] = round(final_confidence)
            return best_match
        else:
            return {"os": "Unknown", "confidence": 0, "match_score": 0, "final_confidence": 0}

    # Example usage:
    # result = OSFingerprintDB.find_match(128, 64240, True, ["mss", "nop", "nop", "sack", "nop", "wscale"])
    # print(f"OS: {result['os']}, Final Confidence: {result['final_confidence']}%")


}
