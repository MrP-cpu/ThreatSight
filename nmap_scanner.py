#!usr/bin/python3

# Import the nmap module
import nmap
import ipaddress
from pprint import pprint

# Initialize the Nmap PortScanner object
scanner = nmap.PortScanner()

print("Welcome to the Nmap Automation Tool")
print("<----------------------------------------->")

while True:
    ip_addr = input("\nEnter IP (or 'quit' to exit): ")
    print("The IP you entered is:", ip_addr)
    if ip_addr.lower() == 'quit':
        break
    scanner.scan(hosts=ip_addr, arguments='-sn')  # Ping scan
    if not scanner.all_hosts():
        print("Host appears to be down")

#check if ip address is valid
    try:
        ipaddress.ip_address(ip_addr)
    except ValueError:
        print("Invalid IP address format")


#type of scan
    resp = input(
    """\nChoose your scan type:
    1) SYN ACK Scan
    2) UDP Scan
    3) Comprehensive Scan\n"""
)

    # Confirm the user's selection
    print("You have entered the option:", resp)

    ports = input("Enter port range (e.g. 1-1000) or leave blank for default (1-1024): ")
    ports = ports if ports else '1-1024'
    

    # Perform a SYN ACK scan if the user selects option 1
    if resp == '1':
        print("Nmap version:", scanner.nmap_version())  # Display the Nmap version being used
        # Perform a SYN ACK scan on the specified IP and port range
        scanner.scan(ip_addr, ports, '-v -sS')

        
        
        # scan information
        print(scanner.scaninfo())
    #status of the IP (e.g., 'up' or 'down')
        print("IP status:", scanner[ip_addr].state())
    # List all detected protocols (e.g., 'tcp', 'udp')
        print("Protocols Found:", scanner[ip_addr].all_protocols())
    # List open ports for the TCP protocol
        print("Open ports:", scanner[ip_addr]['tcp'].keys())

    # Perform a UDP scan if the user selects option 2
    elif resp == '2':
        print("Nmap version:", scanner.nmap_version())  # Display the Nmap version being used
        # Perform a UDP scan on the specified IP and port range
        scanner.scan(ip_addr, ports, '-v -sU')
        
        # Print scan information
        print(scanner.scaninfo())
        # Print the status of the IP (e.g., 'up' or 'down')
        print("IP status:", scanner[ip_addr].state())
        # List all detected protocols (e.g., 'tcp', 'udp')
        print("Protocols Found:", scanner[ip_addr].all_protocols())
        # List open ports for the UDP protocol
        print("Open ports:", scanner[ip_addr]['udp'].keys())

    # Perform a comprehensive scan if the user selects option 3
    elif resp == '3':
        print("Nmap version:", scanner.nmap_version())  # Display the Nmap version being used
        # Perform a comprehensive scan, including version detection, OS detection, and script scanning
        scanner.scan(ip_addr, ports, '-v -sS -sV -O -A')
        
        # Print scan information
        print(scanner.scaninfo())
        # Print the status of the IP (e.g., 'up' or 'down')
        print("IP status:", scanner[ip_addr].state())
        print("Protocols Found:", scanner[ip_addr].all_protocols()) # List all detected protocols (e.g., 'tcp', 'udp')
        
        # Loop through all detected protocols
        for proto in scanner[ip_addr].all_protocols():
            print(f"\nProtocol: {proto.upper()}")  # Print the protocol name in uppercase
            # Get a list of open ports for the current protocol
            ports = scanner[ip_addr][proto].keys()
            # Loop through the ports and print their state (e.g., 'open' or 'closed')
            for port in ports:
                print(f"Port: {port}, State: {scanner[ip_addr][proto][port]['state']}")


else:
    print("Invalid option. Exiting...") # Handle invalid input by the user
