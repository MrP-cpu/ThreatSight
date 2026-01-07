"""
Banner grabbing module for ThreatSight
"""
import socket
import re
from typing import Dict, Optional
from pathlib import Path
import importlib.util

class BannerGrabberPlugin:
    """Base class for all banner grabber plugins"""
    
    def __init__(self):
        self.name = "Base Plugin"
        self.description = "Base banner grabber plugin"
        self.ports = []
        self.protocols = ["tcp"]
    
    def can_handle(self, port: int, protocol: str = "tcp") -> bool:
        return port in self.ports and protocol in self.protocols
    
    def grab_banner(self, target: str, port: int, timeout: float = 3.0) -> Dict:
        raise NotImplementedError("Subclasses must implement grab_banner method")

class HTTPBannerGrabber(BannerGrabberPlugin):
    def __init__(self):
        super().__init__()
        self.name = "HTTP Banner Grabber"
        self.ports = [80, 443, 8080, 8000, 8888]
    
    def grab_banner(self, target: str, port: int, timeout: float = 3.0) -> Dict:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((target, port))
                
                request = f"GET / HTTP/1.0\r\nHost: {target}\r\nUser-Agent: ThreatSight/1.0\r\n\r\n"
                s.send(request.encode())
                
                banner = s.recv(1024)
                return self._parse_banner(banner)
        except Exception as e:
            return {"error": str(e)}
    
    def _parse_banner(self, banner_data: bytes) -> Dict:
        banner_text = banner_data.decode('utf-8', errors='ignore')
        result = {"service": "HTTP", "headers": {}}
        
        lines = banner_text.split('\r\n')
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                result["headers"][key.strip()] = value.strip()
        
        if 'Server' in result["headers"]:
            result["server"] = result["headers"]["Server"]
        
        return result

class PluginManager:
    """Manages banner grabber plugins"""
    
    def __init__(self):
        self.plugins = []
        self._load_builtin_plugins()
    
    def _load_builtin_plugins(self):
        """Load built-in plugins"""
        self.plugins.extend([
            HTTPBannerGrabber(),
            # we can Add other built-in plugins here
        ])
    
    def load_external_plugins(self, plugin_dir: str = "./plugins"):
        """Load external plugins from directory"""
        plugin_dir_path = Path(plugin_dir)
        if not plugin_dir_path.exists():
            return
        
        for plugin_file in plugin_dir_path.glob("*.py"):
            try:
                spec = importlib.util.spec_from_file_location(plugin_file.stem, plugin_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and 
                        issubclass(attr, BannerGrabberPlugin) and 
                        attr != BannerGrabberPlugin):
                        self.plugins.append(attr())
            except Exception as e:
                print(f"Failed to load plugin {plugin_file}: {e}")
    
    def get_plugin_for_port(self, port: int, protocol: str = "tcp") -> Optional[BannerGrabberPlugin]:
        for plugin in self.plugins:
            if plugin.can_handle(port, protocol):
                return plugin
        return None
    
    def grab_banner(self, target: str, port: int, protocol: str = "tcp", timeout: float = 3.0) -> Dict:
        plugin = self.get_plugin_for_port(port, protocol)
        if plugin:
            return plugin.grab_banner(target, port, timeout)
        return {"error": "No plugin available"}
    

    