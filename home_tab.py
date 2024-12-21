import sys
import os
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSpacerItem, QSizePolicy, QListWidget, QTableWidget, QTableWidgetItem
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap
from ping import ping_website
from port_scanner_tab import PortScannerTab
from results_tab import ResultsTab
from domain_info_tab import DomainInfoTab
from sql_injection_checker_tab import SQLInjectionTab
from html_injection_checker_tab import HTMLInjectionTab
from xss_checker_tab import XSSTesterTab

class HomeTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.init_home_tab()

    @staticmethod
    def resource_path(relative_path):
        """Get absolute path to resource, works for development and PyInstaller bundled app"""
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.abspath(".")  # Use the current working directory in development
        return os.path.join(base_path, relative_path)

    def get_public_suffix_list_path(self):
        return self.resource_path('whois/data/public_suffix_list.dat')

    def init_home_tab(self):
        layout = QVBoxLayout()

        # Add spacing above the logo for better balance
        layout.addSpacerItem(QSpacerItem(20, 60, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Load and display the logo (smaller size)
        self.logo_label = QLabel(self)
        logo_path = self.resource_path('assets/red_team_logo.png')
        pixmap = QPixmap(logo_path)
        self.logo_label.setPixmap(pixmap.scaled(250, 250, Qt.AspectRatioMode.KeepAspectRatio))  # Adjust logo path if needed
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.logo_label)

        # Reduce spacing between logo and input box
        layout.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # URL Input box
        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Enter URL")
        self.url_input.setFixedWidth(300)
        self.url_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.url_input.setStyleSheet("padding: 5px; border-radius: 10px;")

        # Center the input box
        input_layout = QHBoxLayout()
        input_layout.addStretch(1)
        input_layout.addWidget(self.url_input)
        input_layout.addStretch(1)
        layout.addLayout(input_layout)

        # Reduce spacing between input box and full scan button
        layout.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Full Scan Button
        self.full_scan_btn = QPushButton("Full Scan", self)
        self.full_scan_btn.clicked.connect(self.full_scan)
        self.full_scan_btn.setFixedWidth(150)
        self.full_scan_btn.setStyleSheet("padding: 10px; border-radius: 10px;")

        # Center Full Scan Button
        full_scan_layout = QHBoxLayout()
        full_scan_layout.addStretch(1)
        full_scan_layout.addWidget(self.full_scan_btn)
        full_scan_layout.addStretch(1)
        layout.addLayout(full_scan_layout)

        # Add some spacing after the full scan button (before the tool buttons)
        layout.addSpacerItem(QSpacerItem(20, 30, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Tool buttons
        tools_layout = QHBoxLayout()
        tool_names = [
            "Domain Info And Subdomains",
            "Port Scanner", "SQL Injection Checker",
            "HTML Injection Checker", "Cross-Site Scripting Checker"
        ]
        for tool in tool_names:
            button = QPushButton(tool, self)
            if tool == "Domain Info And Subdomains":
                button.clicked.connect(self.open_domain_info_tab)
            elif tool == "Port Scanner":
                button.clicked.connect(self.open_port_scanner_tab) # Link to specific method for domain info
            elif tool == "SQL Injection Checker":
                button.clicked.connect(self.open_sql_injection_checker_tab)
            elif tool == "HTML Injection Checker":
                button.clicked.connect(self.open_html_injection_checker_tab)
            elif tool == "Cross-Site Scripting Checker":
                button.clicked.connect(self.open_xss_checker_tab)
            button.setFixedSize(210, 100)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            button.setStyleSheet("padding: 10px; border-radius: 15px;")
            tools_layout.addWidget(button)

        # Center the buttons horizontally with space between them
        layout.addLayout(tools_layout)

        # Add more space below tool buttons for a balanced layout
        layout.addSpacerItem(QSpacerItem(20, 60, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        self.setLayout(layout)

    def open_domain_info_tab(self):
        """Opens the Domain Info and Subdomains Tab."""
        domain_info_tab = DomainInfoTab(self.main_window)
        self.main_window.tabs.addTab(domain_info_tab, f"Domain Info & Subdomains")
        self.main_window.tabs.setCurrentWidget(domain_info_tab)

    def open_port_scanner_tab(self):
        """
        Open the Port Scanner tab and switch to it.
        """
        port_scanner_tab = PortScannerTab(self.main_window)
        self.main_window.tabs.addTab(port_scanner_tab, "Port Scanner")
        self.main_window.tabs.setCurrentWidget(port_scanner_tab)

    def open_sql_injection_checker_tab(self):
        """Opens the Sql Injection Checker Tab."""
        sql_injection_checker_tab = SQLInjectionTab(self.main_window)
        self.main_window.tabs.addTab(sql_injection_checker_tab, f"SQL Injection Checker")
        self.main_window.tabs.setCurrentWidget(sql_injection_checker_tab)

    def open_html_injection_checker_tab(self):
        """Opens the HTML Injection Checker Tab."""
        html_injection_checker_tab = HTMLInjectionTab(self.main_window)
        self.main_window.tabs.addTab(html_injection_checker_tab, f"HTML Injection Checker")
        self.main_window.tabs.setCurrentWidget(html_injection_checker_tab)

    def open_xss_checker_tab(self):
        """Opens the xss Checker Tab."""
        xss_checker_tab = XSSTesterTab(self.main_window)
        self.main_window.tabs.addTab(xss_checker_tab, f"Cross-Site Scripting Checker")
        self.main_window.tabs.setCurrentWidget(xss_checker_tab)


    def full_scan(self):
        url = self.url_input.text()
        if not url:  # If input is empty
            self.show_error("Please enter a URL to proceed.")  # Show error if empty
            return
        print(f"Scanning URL: {url}")  # Debugging output

        # Normalize URL by adding "http://" if it doesn't start with "http"
        if not url.startswith("http"):
            url = "http://" + url

        print(f"Normalized URL: {url}")  # Debugging output

        if not url.startswith("http"):  # Basic validation
            error_tab = QWidget()
            error_layout = QVBoxLayout()

            error_msg = QLabel("Invalid URL, please check and try again.")
            error_layout.addWidget(error_msg)

            back_button = QPushButton("Back to Home", self)
            back_button.clicked.connect(lambda: self.tabs.removeTab(self.tabs.currentIndex()))
            error_layout.addWidget(back_button)

            error_tab.setLayout(error_layout)
            self.tabs.addTab(error_tab, "Error")
            self.tabs.setCurrentWidget(error_tab)
            return

        # Ping the URL to check if it's reachable
        print(f"Pinging URL: {url}")  # Debugging output
        if not ping_website(url):
            error_tab = QWidget()
            error_layout = QVBoxLayout()

            error_msg = QLabel(f"The URL '{url}' is down. Please check and try again.")
            error_layout.addWidget(error_msg)

            back_button = QPushButton("Back to Home", self)
            back_button.clicked.connect(lambda: self.tabs.removeTab(self.tabs.currentIndex()))
            error_layout.addWidget(back_button)

            error_tab.setLayout(error_layout)
            self.tabs.addTab(error_tab, "Error")
            self.tabs.setCurrentWidget(error_tab)
            return

        # Create Full Scan Results Tab
        results_tab = ResultsTab(url, self.main_window)
        self.main_window.tabs.addTab(results_tab, f"Full Scan: {url}")
        self.main_window.tabs.setCurrentWidget(results_tab)

    def show_error(self, message):
        error_tab = QWidget()
        error_layout = QVBoxLayout()
        error_msg = QLabel(message)
        error_layout.addWidget(error_msg)

        back_button = QPushButton("Back to Home", self)
        back_button.clicked.connect(lambda: self.main_window.tabs.removeTab(self.main_window.tabs.currentIndex()))
        error_layout.addWidget(back_button)

        error_tab.setLayout(error_layout)
        self.main_window.tabs.addTab(error_tab, "Error")
        self.main_window.tabs.setCurrentWidget(error_tab)
