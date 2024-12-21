from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QListWidget,
    QLineEdit, QSpacerItem, QSizePolicy, QPushButton, QScrollArea
)
from PyQt6.QtCore import Qt
from domain_info import DomainInfo  # Ensure the correct path for your module

class DomainInfoTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.url_input = None
        self.layout = None
        self.scroll_area = None
        self.find_button = None  # Add find button
        self.init_domain_info_tab()

    def init_domain_info_tab(self):
        """Initialize the tab with input field and layout for domain information."""
        self.layout = QVBoxLayout()

        # Heading for the tab
        heading_label = QLabel("Domain and Subdomain Information", self)
        heading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        heading_label.setStyleSheet("font-size: 24px; font-weight: bold; color: rgb(215, 38, 61);")
        self.layout.addWidget(heading_label)

        # Input box for domain entry
        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Enter domain (e.g., example.com)")
        self.url_input.setStyleSheet("font-size: 16px;")
        self.url_input.setFixedWidth(400)  # Medium size input box
        self.url_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(self.url_input, alignment=Qt.AlignmentFlag.AlignHCenter)

        # Find Button
        self.find_button = QPushButton("Find", self)
        self.find_button.setStyleSheet("font-size: 16px; padding: 5px;")
        self.find_button.clicked.connect(self.on_find_pressed)
        self.layout.addWidget(self.find_button, alignment=Qt.AlignmentFlag.AlignHCenter)

        # Spacer to center content when there are no results
        self.spacer = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        self.layout.addItem(self.spacer)

        # Set up the scroll area to contain the layout
        self.scroll_area = QScrollArea(self)
        self.scroll_area.setWidgetResizable(True)
        scroll_widget = QWidget()  # Create a QWidget to contain the layout
        scroll_widget.setLayout(self.layout)  # Set the layout to the widget
        self.scroll_area.setWidget(scroll_widget)  # Add the widget to the scroll area

        # Set the scroll area as the main layout
        main_layout = QVBoxLayout(self)
        main_layout.addWidget(self.scroll_area)
        self.setLayout(main_layout)

    def on_find_pressed(self):
        """Handle Find button click to display domain info and subdomains."""
        url = self.url_input.text().strip()
        if url:
            url = self.clean_input(url)
            self.clear_previous_results()
            self.url = url
            self.display_domain_info(self.layout)
            self.display_subdomains(self.layout)

    def clean_input(self, input_text):
        """Clean input to remove unwanted characters like [''] formatting."""
        if input_text.startswith("['") and input_text.endswith("']"):
            input_text = input_text[2:-2]  # Remove [' and ']
        return input_text

    def clear_previous_results(self):
        """Clear previous domain information and subdomains from the layout."""
        while self.layout.count() > 3:  # Keep the heading, input box, and button
            widget = self.layout.takeAt(3).widget()
            if widget:
                widget.deleteLater()

    def display_domain_info(self, layout):
        """Fetch and display domain information in a table."""
        domain_info_container = QVBoxLayout()
        domain_info_label = QLabel("Domain Information", self)
        domain_info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        domain_info_label.setStyleSheet("font-size: 18px; font-weight: bold; color: rgb(215, 38, 61);")
        domain_info_container.addWidget(domain_info_label)

        try:
            # Use DomainInfo to fetch domain information
            domain_info = DomainInfo(self.url)
            dom_info = domain_info.find_dom_info()

            if "Error" in dom_info:
                error_msg = QLabel(f"Failed to fetch domain information: {dom_info['Error']}", self)
                domain_info_container.addWidget(error_msg)
                layout.addLayout(domain_info_container)
                return

            if isinstance(dom_info, dict):
                # Add IP address to domain information
                ip_address = domain_info.dom_to_ip()
                dom_info["IP Address"] = ip_address if isinstance(ip_address, str) else "Could not resolve IP"

                # Domain Information Table
                domain_info_table = QTableWidget(len(dom_info), 2, self)
                domain_info_table.setHorizontalHeaderLabels(["Type", "Information"])

                for i, (key, value) in enumerate(dom_info.items()):
                    domain_info_table.setItem(i, 0, QTableWidgetItem(key))
                    domain_info_table.setItem(i, 1, QTableWidgetItem(str(value)))

                domain_info_table.horizontalHeader().setStretchLastSection(True)
                domain_info_table.resizeColumnsToContents()
                domain_info_table.setSizeAdjustPolicy(QTableWidget.SizeAdjustPolicy.AdjustToContents)
                domain_info_container.addWidget(domain_info_table)
            else:
                raise ValueError("Domain information must be a dictionary.")

        except Exception as e:
            error_msg = QLabel(f"Failed to fetch domain information: {str(e)}", self)
            domain_info_container.addWidget(error_msg)

        layout.addLayout(domain_info_container)

    def display_subdomains(self, layout):
        """Fetch and display subdomains in a list."""
        subdomain_container = QVBoxLayout()
        subdomain_label = QLabel("Subdomains", self)
        subdomain_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subdomain_label.setStyleSheet("font-size: 18px; font-weight: bold; color: rgb(215, 38, 61);")
        subdomain_container.addWidget(subdomain_label)

        try:
            # Use DomainInfo to fetch subdomains
            domain_info = DomainInfo(self.url)
            subdomains = domain_info.subdom()

            if isinstance(subdomains, set) and subdomains:
                cleaned_subdomains = [self.clean_input(sub) for sub in subdomains]
                subdomain_list = QListWidget(self)
                subdomain_list.addItems(cleaned_subdomains)
                subdomain_list.setFixedHeight(subdomain_list.sizeHintForRow(0) * len(cleaned_subdomains) + 2)
                subdomain_container.addWidget(subdomain_list)
            else:
                raise ValueError("Subdomains must be a non-empty set.")

        except Exception as e:
            error_msg = QLabel(f"Failed to fetch subdomains: {str(e)}", self)
            subdomain_container.addWidget(error_msg)

        layout.addLayout(subdomain_container)
