#!/usr/bin/env python3

## ESSENTIAL LIBRARIES ##
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import time
from colorama import Fore, Style, init


## VALIDATION OF IP ADDRESS ##

def get_target_ip():
    while True:
        ip=input("Enter the Target IP").strip()
        parts=ip.split('.')
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <=255 for p in parts): #Basic IP validation
            return ip
        print(f"Invalid IP address format. Try again")



## BASIC STRUCTURE OF SOCKET FOR TCP SCAN ##
def scan_port(ip,port):
    
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(1) #this will wait till time you defined
            result=s.connect_ex((ip,port))
            if result==0:
                print(f"port {port} is open")
                return port
    except Exception:
        pass
    return None


## MULTITHREADING ADDED ##
def threaded_scan(ip , start_port , end_port , max_threads=100):
    open_ports = []
    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
            
        for future in tqdm(as_completed(futures), total=len(ports), desc="Scanning Ports"):
            port = futures[future]
            result = future.result()
            if result:
                print(f"Port {port} is open")
                open_ports.append(result)

    return open_ports


def main():
    target_ip=get_target_ip()
    start_port=1
    end_port=63000
    open_ports=[]

    start_time = time.time()
    open_ports = threaded_scan(target_ip, start_port, end_port, max_threads=500)
    end_time = time.time()

    print(f"\nOpen ports on {target_ip}: {open_ports}")
    print(f"Scan completed in {end_time - start_time:.2f} seconds")


if __name__ == "__main__":
    main()