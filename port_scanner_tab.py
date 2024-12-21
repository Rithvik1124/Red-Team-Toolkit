import sys
import threading
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QLineEdit, QSpacerItem,
    QSizePolicy, QScrollArea, QPushButton, QHBoxLayout, QTextEdit
)
from PyQt6.QtCore import Qt
from port_scanner import scan_tcp_ports, scan_udp_ports, quick_scan


class RedirectConsoleOutput:
    """
    Redirects the console output to a QTextEdit widget.
    """
    def __init__(self, text_edit: QTextEdit):
        self.text_edit = text_edit

    def write(self, text):
        """Write text to the QTextEdit widget."""
        self.text_edit.append(text.strip())

    def flush(self):
        """Flush method required for file-like objects."""
        pass


class PortScannerTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.url_input = None
        self.layout = None
        self.scroll_area = None
        self.results_table = None
        self.logs_output = None  # QTextEdit for logs
        self.init_port_scanner_tab()

    def init_port_scanner_tab(self):
        """Initialize the Port Scanner tab."""
        self.layout = QVBoxLayout()

        # Heading for the tab
        heading_label = QLabel("Port Scanner", self)
        heading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        heading_label.setStyleSheet("font-size: 24px; font-weight: bold; color: rgb(215, 38, 61);")
        self.layout.addWidget(heading_label)

        # Input box for target entry
        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Enter target (e.g., example.com)")
        self.url_input.setStyleSheet("font-size: 16px;")
        self.url_input.setFixedWidth(400)
        self.url_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(self.url_input, alignment=Qt.AlignmentFlag.AlignHCenter)

        # Scan Buttons
        button_layout = QHBoxLayout()
        tcp_scan_button = QPushButton("TCP Scan", self)
        tcp_scan_button.clicked.connect(lambda: self.start_scan("TCP"))
        udp_scan_button = QPushButton("UDP Scan", self)
        udp_scan_button.clicked.connect(lambda: self.start_scan("UDP"))
        quick_scan_button = QPushButton("Quick Scan", self)
        quick_scan_button.clicked.connect(lambda: self.start_scan("Quick"))

        button_layout.addWidget(tcp_scan_button)
        button_layout.addWidget(udp_scan_button)
        button_layout.addWidget(quick_scan_button)
        self.layout.addLayout(button_layout)

        # Permanent Results Table
        self.results_table = QTableWidget(self)
        self.results_table.setColumnCount(3)  # Add another column for Service
        self.results_table.setHorizontalHeaderLabels(["Port", "Service", "Status"])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setStyleSheet("font-size: 14px;")
        self.layout.addWidget(self.results_table)

        # Logs Section
        logs_label = QLabel("Logs", self)
        logs_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logs_label.setStyleSheet("font-size: 18px; font-weight: bold; color: rgb(215, 38, 61);")
        self.layout.addWidget(logs_label)

        self.logs_output = QTextEdit(self)
        self.logs_output.setReadOnly(True)
        self.logs_output.setStyleSheet("font-size: 14px; background-color: rgb(30, 30, 36); color: rgb(255, 255, 255);")
        self.layout.addWidget(self.logs_output)

        # Add a spacer to center content
        self.layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Set up the scroll area for results
        self.scroll_area = QScrollArea(self)
        scroll_widget = QWidget()
        scroll_widget.setLayout(self.layout)
        self.scroll_area.setWidget(scroll_widget)
        self.scroll_area.setWidgetResizable(True)

        # Main Layout
        main_layout = QVBoxLayout(self)
        main_layout.addWidget(self.scroll_area)
        self.setLayout(main_layout)

        # Redirect stdout to logs_output
        sys.stdout = RedirectConsoleOutput(self.logs_output)

    def start_scan(self, scan_type):
        """Start the appropriate scan based on scan type (TCP, UDP, or Quick)."""
        target = self.url_input.text().strip()
        if not target:
            self.display_error("Please enter a valid target.")
            return

        print(f"Starting {scan_type} scan...")
        if scan_type == "TCP":
            threading.Thread(target=self.tcp_scan, args=(target,), daemon=True).start()
        elif scan_type == "UDP":
            threading.Thread(target=self.udp_scan, args=(target,), daemon=True).start()
        elif scan_type == "Quick":
            threading.Thread(target=self.quick_scan, args=(target,), daemon=True).start()

    def tcp_scan(self, target):
        """Perform a TCP scan."""
        print(f"Performing TCP scan for {target}")
        scan_tcp_ports(target, (1, 1024), self.update_table)
        print("TCP scan completed.")

    def udp_scan(self, target):
        """Perform a UDP scan."""
        print(f"Performing UDP scan for {target}")
        scan_udp_ports(target, (1, 1024), self.update_table)
        print("UDP scan completed.")

    def quick_scan(self, target):
        """Perform a Quick scan."""
        print(f"Performing Quick scan for {target}")
        results = quick_scan(target)
        print("Quick scan completed.")
        for port, service in results.items():
            self.update_table(port, service)

    def update_table(self, port, service):
        """Update the results table with a new open port and its service."""
        # Check if the port is already in the table
        row_count = self.results_table.rowCount()
        for row in range(row_count):
            if self.results_table.item(row, 0) and self.results_table.item(row, 0).text() == str(port):
                return  # Port already in table, no need to add it again

        # Add new row for the open port
        row_position = self.results_table.rowCount()
        self.results_table.insertRow(row_position)
        self.results_table.setItem(row_position, 0, QTableWidgetItem(str(port)))  # Port
        self.results_table.setItem(row_position, 1, QTableWidgetItem(service))  # Service
        self.results_table.setItem(row_position, 2, QTableWidgetItem("Open"))  # Status

        # Ensure table content is resized properly
        self.results_table.resizeColumnsToContents()

    def display_error(self, message):
        """Display an error message in the results table."""
        print(f"Error: {message}")
        self.results_table.clearContents()
        self.results_table.setRowCount(1)
        self.results_table.setItem(0, 0, QTableWidgetItem("Error"))
        self.results_table.setItem(0, 1, QTableWidgetItem(message))
        self.results_table.setItem(0, 2, QTableWidgetItem(""))
