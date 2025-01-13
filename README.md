# Nmap Automation Tool

Welcome to the **Nmap Automation Tool**, a Python script designed to simplify network scanning tasks using the powerful `nmap` library. This tool provides a user-friendly interface to perform different types of scans on a specified IP address, making it easier for network administrators and cybersecurity enthusiasts to explore and analyze their networks.

---

## Features

- **SYN ACK Scan**: Quickly identifies open TCP ports by sending SYN packets and analyzing responses.
- **UDP Scan**: Scans for open UDP ports within the specified range.
- **Comprehensive Scan**: Performs detailed scans including service version detection, OS detection, and script scanning.

---

## Requirements

To use this tool, ensure the following are installed and configured on your system:

- **Python**: Version 3 or later.
- **Nmap**: Download and install Nmap from [Nmap's official website](https://nmap.org/download.html).
- **python-nmap**: Install the Python wrapper for Nmap using the following command:
  ```bash
  pip install python-nmap
  ```

---

## Usage

1. Clone or download this repository.
2. Run the script using Python 3:
   ```bash
   python3 nmap_automation_tool.py
   ```
3. Follow the on-screen instructions:
   - Enter the IP address you want to scan.
   - Choose the type of scan to perform:
     - **1**: SYN ACK Scan
     - **2**: UDP Scan
     - **3**: Comprehensive Scan

---

## Example Output

### SYN ACK Scan:
```
Please enter the IP address to scan: 192.168.1.1
You have entered the option: 1
Nmap version: (7, 93)
Scan information: {'tcp': {'method': 'syn', 'services': '1-1024'}}
IP status: up
Protocols Found: ['tcp']
Open ports: dict_keys([22, 80, 443])
```

### UDP Scan:
```
Please enter the IP address to scan: 192.168.1.1
You have entered the option: 2
Nmap version: (7, 93)
Scan information: {'udp': {'method': 'udp', 'services': '1-1024'}}
IP status: up
Protocols Found: ['udp']
Open ports: dict_keys([53, 123])
```

### Comprehensive Scan:
```
Please enter the IP address to scan: 192.168.1.1
You have entered the option: 3
Nmap version: (7, 93)
Scan information: {'tcp': {'method': 'syn', 'services': '1-1024'}}
IP status: up
Protocols Found: ['tcp']

Protocol: TCP
Port: 22, State: open
Port: 80, State: open
Port: 443, State: open
```

---

## Notes

- Ensure you have the necessary permissions to scan the target IP address. Unauthorized scanning may violate local or international laws.
- Use this tool responsibly and within the bounds of ethical guidelines.

---

## Troubleshooting

1. **Nmap is not installed**:
   - Ensure Nmap is installed and accessible in your system's PATH.
2. **Permission denied**:
   - Some scans may require administrative privileges. Run the script with elevated permissions (e.g., using `sudo` on Linux).
3. **Firewall blocking scans**:
   - Target firewalls may block certain types of scans, leading to incomplete results.

---

## License

This project is open-source and available under the MIT License. Feel free to modify and adapt it to your needs.

---

## Author

**Parshant Kumar**  
Technical Secretary at OWASP_TIET

For queries or suggestions, feel free to reach out or contribute to the project. Enjoy secure and efficient network exploration!

