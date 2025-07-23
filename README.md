---

# Nmap Automation Tool

Welcome to the **Nmap Automation Tool**, a Python-based network scanning utility that simplifies and automates powerful `nmap` scans. This tool provides an interactive interface for performing ping checks and multiple types of scans, making it ideal for network administrators, cybersecurity enthusiasts, and ethical hackers.

---

## Features

* **Ping Detection**: Checks if the host is alive before scanning.
* **IP Validation**: Verifies if the entered IP address is syntactically valid.
* **Optional Port Range**: Allows scanning custom or default port ranges (defaults to 1-1024).
* **SYN ACK Scan**: Quickly identifies open TCP ports by sending SYN packets and analyzing responses.
* **UDP Scan**: Scans for open UDP ports in the provided port range.
* **Comprehensive Scan**: Performs deep analysis including service version detection, OS fingerprinting, and script scanning.

---

## Requirements

Make sure you have the following installed:

* **Python**: Version 3 or later.
* **Nmap**: Command-line tool must be installed and accessible via system path.
* **python-nmap**: Python wrapper for `nmap`. Install it via:

  ```bash
  pip install python-nmap
  ```

---

## Usage

1. Clone or download this repository.
2. Run the script with Python 3:

   ```bash
   python3 nmap_scanner.py
   ```
3. Follow the interactive prompt:

   * Enter the target IP address (or type `quit` to exit).
   * If the IP is reachable and valid, choose a scan type:

     * **1**: SYN ACK Scan
     * **2**: UDP Scan
     * **3**: Comprehensive Scan
   * Enter a port range or press Enter to use the default `1-1024`.

---

## Example Output

### When Host is Down or Invalid:

```
Enter IP (or 'quit' to exit): 192.168.5.200
The IP you entered is: 192.168.5.200
Host appears to be down
Invalid IP address format
```

### SYN ACK Scan:

```
Enter IP (or 'quit' to exit): 192.168.1.1
The IP you entered is: 192.168.1.1

Choose your scan type:
1) SYN ACK Scan
2) UDP Scan
3) Comprehensive Scan

You have entered the option: 1
Enter port range (e.g. 1-1000) or leave blank for default (1-1024): 
Nmap version: (7, 93)
Scan information: {'tcp': {'method': 'syn', 'services': '1-1024'}}
IP status: up
Protocols Found: ['tcp']
Open ports: dict_keys([22, 80, 443])
```

### UDP Scan:

```
You have entered the option: 2
Enter port range (e.g. 1-1000) or leave blank for default (1-1024): 1-100
Nmap version: (7, 93)
Scan information: {'udp': {'method': 'udp', 'services': '1-100'}}
IP status: up
Protocols Found: ['udp']
Open ports: dict_keys([53])
```

### Comprehensive Scan:

```
You have entered the option: 3
Enter port range (e.g. 1-1000) or leave blank for default (1-1024): 
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

## ⚠️ Notes

* **Legal Warning**: Scanning networks you do not own or have explicit permission to analyze is illegal in many jurisdictions.
* Ensure you have administrative privileges when running advanced scans.
* Use responsibly and ethically for testing, auditing, or research purposes.

---

## Troubleshooting

* **Nmap not found**:
  Ensure Nmap is installed and added to your system’s `PATH`.

* **Permission issues**:
  Use `sudo` or run with elevated privileges if certain scans fail.

* **No open ports or host down**:
  The host might be firewalled or unresponsive to ICMP (ping) requests.

---

## 📄 License

This project is licensed under the **MIT License**. You are free to modify and use it for both personal and professional purposes.

---

## 👤 Author

**Parshant Kumar**
Technical Secretary at OWASP\_TIET

Feel free to contribute, open issues, or suggest improvements. Happy scanning! 🕵️‍♂️

---

