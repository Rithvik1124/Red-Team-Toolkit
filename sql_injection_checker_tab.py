import sys
import threading
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QLineEdit,
    QSpacerItem, QSizePolicy, QScrollArea, QPushButton, QHBoxLayout, QTextEdit
)
from PyQt6.QtCore import Qt
from sql_inj_check import SQLInjectionTester


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


class SQLInjectionTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.layout = None
        self.results_table = None
        self.url_input = None
        self.payload_input = None
        self.tester = None  # SQLInjectionTester instance
        self.logs_output = None  # QTextEdit for logs
        self.init_ui()

    def init_ui(self):
        """Initialize the UI for the SQL Injection Tester tab."""
        self.layout = QVBoxLayout()

        # Heading for the tab
        heading_label = QLabel("SQL Injection Tester", self)
        heading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        heading_label.setStyleSheet("font-size: 24px; font-weight: bold; color: rgb(215, 38, 61);")
        self.layout.addWidget(heading_label)

        # Input field for target URL
        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText("Enter target URL (e.g., http://example.com/login.php)")
        self.url_input.setStyleSheet("font-size: 16px;")
        self.url_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(self.url_input)

        # Buttons for actions
        button_layout = QHBoxLayout()
        extract_button = QPushButton("Extract Input Fields", self)
        extract_button.clicked.connect(self.start_extraction)
        test_button = QPushButton("Test Payloads", self)
        test_button.clicked.connect(self.start_testing)
        button_layout.addWidget(extract_button)
        button_layout.addWidget(test_button)
        self.layout.addLayout(button_layout)

        # Permanent Results Table
        self.results_table = QTableWidget(self)
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["Field Name", "Payload", "Result"])
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
        self.logs_output.setStyleSheet("font-size: 14px; background-color: rgb(30, 30, 36);")
        self.layout.addWidget(self.logs_output)

        # Add a spacer to center content
        self.layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Set up the scroll area for results
        scroll_area = QScrollArea(self)
        scroll_widget = QWidget()
        scroll_widget.setLayout(self.layout)
        scroll_area.setWidget(scroll_widget)
        scroll_area.setWidgetResizable(True)

        # Main Layout
        main_layout = QVBoxLayout(self)
        main_layout.addWidget(scroll_area)
        self.setLayout(main_layout)

        # Redirect stdout to logs_output
        sys.stdout = RedirectConsoleOutput(self.logs_output)

    def start_extraction(self):
        """Start input field extraction in a thread."""
        target_url = self.url_input.text().strip()
        if not target_url:
            self.display_error("Please enter a valid target URL.")
            return

        payloads = {
            "1": ["Error Based Payload", "' OR '1'='1"],
            
        }
        self.tester = SQLInjectionTester(target_url, payloads)
        print("[INFO] Starting input field extraction...")
        threading.Thread(target=self.extract_fields, daemon=True).start()

    def extract_fields(self):
        """Extract input field names and display them in the table."""
        try:
            self.tester.extract_input_field_names()
            self.display_extraction_results(self.tester.field_names)
        except Exception as e:
            print(f"[ERROR] Exception during extraction: {e}")
            self.display_error(f"Error during extraction: {e}")

    def display_extraction_results(self, field_names):
        """Display extracted input field names in the table."""
        print(f"[INFO] Extracted input fields: {field_names}")
        self.results_table.clearContents()
        self.results_table.setRowCount(len(field_names))

        for row, field_name in enumerate(field_names):
            self.results_table.setItem(row, 0, QTableWidgetItem(field_name))
            self.results_table.setItem(row, 1, QTableWidgetItem("Extracted"))
            self.results_table.setItem(row, 2, QTableWidgetItem(""))

    def start_testing(self):
        """Start payload testing in a thread."""
        if not self.tester or not self.tester.field_names:
            self.display_error("No input fields to test. Extract input fields first.")
            return

        print("[INFO] Starting payload testing...")
        threading.Thread(target=self.test_payloads, daemon=True).start()

    def test_payloads(self):
        """Test the payloads on the extracted input fields."""
        try:
            self.tester.test_payloads()
            self.display_testing_results(self.tester.results)
        except Exception as e:
            print(f"[ERROR] Exception during testing: {e}")
            self.display_error(f"Error during testing: {e}")

    def display_testing_results(self, results):
        """Display testing results for the input fields."""
        print("[INFO] Testing completed. Displaying results.")
        self.results_table.clearContents()
        self.results_table.setRowCount(len(results))

        for row, (field_name, payload, result) in enumerate(results):
            self.results_table.setItem(row, 0, QTableWidgetItem(field_name))
            self.results_table.setItem(row, 1, QTableWidgetItem(payload))
            self.results_table.setItem(row, 2, QTableWidgetItem(result))

    def display_error(self, message):
        """Display an error message in the results table."""
        print(f"[ERROR] {message}")
        self.results_table.clearContents()
        self.results_table.setRowCount(1)
        self.results_table.setItem(0, 0, QTableWidgetItem("Error"))
        self.results_table.setItem(0, 1, QTableWidgetItem(""))
        self.results_table.setItem(0, 2, QTableWidgetItem(message))
