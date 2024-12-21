from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QScrollArea, QSizePolicy
from PyQt6.QtCore import Qt, QTimer
from domain_info import DomainInfo
from port_scanner import quick_scan
from sql_inj_check import SQLInjectionTester
from html_injection_tester import HtmlInjectionTester
from xss_tester import XSSTester
import threading


class ResultsTab(QWidget):
    def __init__(self, url, main_window):
        super().__init__()
        self.url = url
        self.main_window = main_window
        self.layout = QVBoxLayout()

        # Add Heading
        heading_label = QLabel(f"Results for: {self.url}", self)
        heading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        heading_label.setStyleSheet("font-size: 24px; font-weight: bold; color: rgb(215, 38, 61);")
        self.layout.addWidget(heading_label)

        # Start running the scans
        threading.Thread(target=self.run_full_scan, daemon=True).start()

        # Add a scrollable layout for results
        scroll_area = QScrollArea(self)
        scroll_widget = QWidget()
        scroll_widget.setLayout(self.layout)
        scroll_area.setWidget(scroll_widget)
        scroll_area.setWidgetResizable(True)

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(scroll_area)
        self.setLayout(main_layout)

    def run_full_scan(self):
        QTimer.singleShot(0, self.add_domain_info)
        QTimer.singleShot(0, self.add_port_scan_results)
        QTimer.singleShot(0, self.add_sql_injection_results)
        QTimer.singleShot(0, self.add_html_injection_results)
        QTimer.singleShot(0, self.add_xss_injection_results)

    def add_domain_info(self):
        # Fetch domain info
        domain_info_container = QVBoxLayout()
        domain_info_label = QLabel("Domain Information", self)
        domain_info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        domain_info_label.setStyleSheet("font-size: 18px; font-weight: bold; color: rgb(215, 38, 61);")
        domain_info_container.addWidget(domain_info_label)

        try:
            domain_info = DomainInfo(self.url)
            dom_info = domain_info.find_dom_info()
            if "Error" in dom_info:
                error_msg = QLabel(f"Failed to fetch domain information: {dom_info['Error']}", self)
                domain_info_container.addWidget(error_msg)
            else:
                ip_address = domain_info.dom_to_ip()
                dom_info["IP Address"] = ip_address if isinstance(ip_address, str) else "Could not resolve IP"

                table = QTableWidget(len(dom_info), 2, self)
                table.setHorizontalHeaderLabels(["Type", "Information"])
                table.setFixedHeight(300)
                for i, (key, value) in enumerate(dom_info.items()):
                    table.setItem(i, 0, QTableWidgetItem(key))
                    table.setItem(i, 1, QTableWidgetItem(str(value)))
                table.horizontalHeader().setStretchLastSection(True)
                table.resizeColumnsToContents()
                domain_info_container.addWidget(table)
        except Exception as e:
            domain_info_container.addWidget(QLabel(f"Error fetching domain info: {e}"))

        self.layout.addLayout(domain_info_container)

    def add_port_scan_results(self):
        # Perform quick scan
        port_scan_container = QVBoxLayout()
        port_scan_label = QLabel("Port Scan Results (Quick Scan)", self)
        port_scan_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        port_scan_label.setStyleSheet("font-size: 18px; font-weight: bold; color: rgb(215, 38, 61);")
        port_scan_container.addWidget(port_scan_label)

        try:
            results = quick_scan(self.url)
            table = QTableWidget(len(results), 2, self)
            table.setHorizontalHeaderLabels(["Port", "Service"])
            table.setFixedHeight(300)
            for i, (port, service) in enumerate(results.items()):
                table.setItem(i, 0, QTableWidgetItem(str(port)))
                table.setItem(i, 1, QTableWidgetItem(service))
            table.horizontalHeader().setStretchLastSection(True)
            table.resizeColumnsToContents()
            port_scan_container.addWidget(table)
        except Exception as e:
            port_scan_container.addWidget(QLabel(f"Error performing port scan: {e}"))

        self.layout.addLayout(port_scan_container)

    def add_sql_injection_results(self):
        # Test SQL Injection
        sql_injection_container = QVBoxLayout()
        sql_injection_label = QLabel("SQL Injection Results", self)
        sql_injection_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sql_injection_label.setStyleSheet("font-size: 18px; font-weight: bold; color: rgb(215, 38, 61);")
        sql_injection_container.addWidget(sql_injection_label)

        try:
            tester = SQLInjectionTester(self.url, {
                "1": ["Error Based Payload", "' OR '1'='1"],
                "2": ["Basic Payload", "' OR 1=1 --"]
            })
            tester.extract_input_field_names()
            tester.test_payloads()

            if not tester.results:
                sql_injection_container.addWidget(QLabel("No vulnerabilities found or testing failed."))
            else:
                table = QTableWidget(len(tester.results), 3, self)
                table.setHorizontalHeaderLabels(["Field Name", "Payload", "Result"])
                table.setFixedHeight(300)
                for i, (field_name, payload, result) in enumerate(tester.results):
                    table.setItem(i, 0, QTableWidgetItem(field_name))
                    table.setItem(i, 1, QTableWidgetItem(payload))
                    table.setItem(i, 2, QTableWidgetItem(result))
                table.horizontalHeader().setStretchLastSection(True)
                table.resizeColumnsToContents()
                sql_injection_container.addWidget(table)

        except Exception as e:
            sql_injection_container.addWidget(QLabel(f"Error testing SQL Injection: {e}"))

        self.layout.addLayout(sql_injection_container)

    def add_html_injection_results(self):
        # Test HTML Injection
        html_injection_container = QVBoxLayout()
        html_injection_label = QLabel("HTML Injection Results", self)
        html_injection_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        html_injection_label.setStyleSheet("font-size: 18px; font-weight: bold; color: rgb(215, 38, 61);")
        html_injection_container.addWidget(html_injection_label)

        try:
            tester = HtmlInjectionTester(self.url)
            tester.extract_input_fields()
            tester.test_injection()

            table = QTableWidget(len(tester.results), 2, self)
            table.setHorizontalHeaderLabels(["Field Name", "Result"])
            table.setFixedHeight(300)
            for i, (field_name, result) in enumerate(tester.results):
                table.setItem(i, 0, QTableWidgetItem(field_name))
                table.setItem(i, 1, QTableWidgetItem(result))
            table.horizontalHeader().setStretchLastSection(True)
            table.resizeColumnsToContents()
            html_injection_container.addWidget(table)
        except Exception as e:
            html_injection_container.addWidget(QLabel(f"Error testing HTML Injection: {e}"))

        self.layout.addLayout(html_injection_container)

    def add_xss_injection_results(self):
        # Test XSS Injection
        xss_container = QVBoxLayout()
        xss_label = QLabel("XSS Injection Results", self)
        xss_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        xss_label.setStyleSheet("font-size: 18px; font-weight: bold; color: rgb(215, 38, 61);")
        xss_container.addWidget(xss_label)

        try:
            tester = XSSTester(self.url)
            tester.extract_input_fields()
            tester.test_xss()

            table = QTableWidget(len(tester.results), 2, self)
            table.setHorizontalHeaderLabels(["Field Name", "Result"])
            table.setFixedHeight(300)
            for i, (field_name, result) in enumerate(tester.results):
                table.setItem(i, 0, QTableWidgetItem(field_name))
                table.setItem(i, 1, QTableWidgetItem(result))
            table.horizontalHeader().setStretchLastSection(True)
            table.resizeColumnsToContents()
            xss_container.addWidget(table)
        except Exception as e:
            xss_container.addWidget(QLabel(f"Error testing XSS Injection: {e}"))

        self.layout.addLayout(xss_container)
