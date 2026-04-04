import socket
from typing import Dict, List, Any
from dataclasses import dataclass
import struct

@dataclass
class OSFingerprint:
    """Data class for OS fingerprint characteristics"""
    os: str
    ttl: int
    window_size: int
    df: bool
    options: List[str]
    confidence: int

class OSFingerprintDB:
    """Database for OS fingerprint detection"""
    
    OS_FINGERPRINTS = [
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
            "os": "Solaris 2.5.1 - 2.8",
            "ttl": 255,
            "window_size": 8760,
            "df": True,
            "options": ["mss", "nop", "wscale", "nop", "nop", "sack"],
            "confidence": 85
        },
        {
            "os": "Windows 98",
            "ttl": 128,
            "window_size": 8192,
            "df": True,
            "options": ["mss", "nop", "nop", "sack"],
            "confidence": 80
        },
        {
            "os": "FreeBSD 5",
            "ttl": 64,
            "window_size": 65535,
            "df": True,
            "options": ["mss", "nop", "wscale", "sack", "ts"],
            "confidence": 82
        }
    ]
    
    @classmethod
    def find_match(cls, ttl: int, window_size: int, df: bool, options: List[str]) -> Dict[str, Any]:
        """Find the best OS match based on fingerprint characteristics."""
        best_match = None
        best_score = 0
        
        for fingerprint in cls.OS_FINGERPRINTS:
            score = 0
            
            # TTL scoring (exact match = 40 points, close = 20)
            if fingerprint["ttl"] == ttl:
                score += 40
            elif abs(fingerprint["ttl"] - ttl) <= 16:  # Allow small variation
                score += 20
            
            # Window size scoring (close match = 30 points)
            if abs(fingerprint["window_size"] - window_size) <= 1000:
                score += 30
            elif abs(fingerprint["window_size"] - window_size) <= 5000:
                score += 15
            
            # DF flag scoring (10 points)
            if fingerprint["df"] == df:
                score += 10
            
            # TCP options scoring (20 points)
            common_options = set(fingerprint["options"]) & set(options)
            if common_options:
                score += (len(common_options) / len(fingerprint["options"])) * 20
            
            if score > best_score:
                best_score = score
                best_match = fingerprint.copy()
                best_match["match_score"] = score
        
        if best_match:
            # Calculate final confidence
            final_confidence = (best_match["confidence"] * (best_score / 100))
            best_match["final_confidence"] = round(final_confidence)
            return best_match
        else:
            return {
                "os": "Unknown", 
                "confidence": 0, 
                "match_score": 0, 
                "final_confidence": 0,
                "ttl": ttl,
                "window_size": window_size,
                "df": df,
                "options": options
            }
    
    @classmethod
    def detect_from_packet(cls, packet_data: bytes) -> Dict[str, Any]:
        """Extract fingerprint from raw TCP packet."""
        try:
            # Parse IP header (20 bytes minimum)
            ip_header = packet_data[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            ttl = iph[5]
            protocol = iph[6]
            
            if protocol != 6:  # Not TCP
                return {"error": "Not a TCP packet"}
            
            # Parse TCP header (20 bytes minimum)
            tcp_header = packet_data[20:40]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            
            window_size = tcph[6]
            
            # Extract TCP options (complicated, simplified here)
            data_offset = (tcph[4] >> 4) * 4
            options = []
            if data_offset > 20:
                # Simplified - real parsing needed
                options = ["mss", "nop"]  # Placeholder
            
            # DF flag from IP header
            df = (iph[3] & 0x4000) != 0
            
            return cls.find_match(ttl, window_size, df, options)
            
        except Exception as e:
            return {"error": f"Packet parsing failed: {str(e)}"}


# Example usage
if __name__ == "__main__":
    # Test the OS detection
    result = OSFingerprintDB.find_match(
        ttl=128,
        window_size=64240,
        df=True,
        options=["mss", "nop", "nop", "sack", "nop", "wscale"]
    )
    print(f"Detected OS: {result['os']} (Confidence: {result['final_confidence']}%)")