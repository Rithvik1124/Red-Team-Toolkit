# File: port_scanner.py

import socket
from datetime import datetime
from PyQt6.QtCore import QTimer

# Commonly used ports for a quick scan
COMMON_PORTS = {
    20: "FTP (Data Transfer)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
}

# TCP and UDP ranges
TCP_PORT_RANGE = (0, 65535)  # TCP well-known, registered, and dynamic ports
UDP_PORT_RANGE = (0, 65535)  # UDP well-known, registered, and dynamic ports



def scan_tcp_ports(target: str, port_range: tuple, update_callback):
    """
    Scan TCP ports on the specified target within the given range and update the table in real-time.
    """
    print("-" * 50)
    print(f"Scanning TCP Ports on Target: {target}")
    print("Scanning started at:", str(datetime.now()))
    print("-" * 50)

    for port in range(port_range[0], port_range[1] + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown Service")
                QTimer.singleShot(0, lambda: update_callback(port, service))  # Call update_table safely
                print(f"TCP Port {port} ({service}) is open")
            s.close()
        except KeyboardInterrupt:
            print("\nExiting Program!")
            return
        except socket.gaierror:
            print("\nHostname Could Not Be Resolved!")
            return
        except socket.error:
            print("\nServer not responding!")
            return


def scan_udp_ports(target: str, port_range: tuple, update_callback):
    """
    Scan UDP ports on the specified target within the given range and update the table in real-time.
    """
    print("-" * 50)
    print(f"Scanning UDP Ports on Target: {target}")
    print("Scanning started at:", str(datetime.now()))
    print("-" * 50)

    for port in range(port_range[0], port_range[1] + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            socket.setdefaulttimeout(1)
            s.sendto(b"ping", (target, port))
            try:
                data, _ = s.recvfrom(1024)
                service = COMMON_PORTS.get(port, "Unknown Service")
                QTimer.singleShot(0, lambda: update_callback(port, service))  # Call update_table safely
                print(f"UDP Port {port} ({service}) is open")
            except socket.timeout:
                pass  # UDP may not respond even if open
            s.close()
        except KeyboardInterrupt:
            print("\nExiting Program!")
            return
        except socket.gaierror:
            print("\nHostname Could Not Be Resolved!")
            return
        except socket.error:
            print("\nServer not responding!")
            return



def quick_scan(target: str):
    """
    Perform a quick scan on commonly used ports and return results as a dictionary.
    """
    results = {}
    print("-" * 50)
    print(f"Performing Quick Scan on Target: {target}")
    print("Scanning started at:", str(datetime.now()))
    print("-" * 50)

    for port, service in COMMON_PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                results[port] = service
                print(f"TCP Port {port} ({service}) is open")
            s.close()
        except KeyboardInterrupt:
            print("\nExiting Program!")
            break
        except socket.gaierror:
            print("\nHostname Could Not Be Resolved!")
            results["Error"] = "Hostname Could Not Be Resolved"
            break
        except socket.error:
            print("\nServer not responding!")
            results["Error"] = "Server not responding"
            break

    return results
