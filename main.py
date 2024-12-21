import sys

from PyQt6.QtWidgets import QApplication, QMainWindow, QTabWidget

from home_tab import HomeTab


class ScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Web Security Scanner")
        self.setGeometry(100, 100, 800, 600)

        # Main tab widget
        self.tabs = QTabWidget(self)
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.setCentralWidget(self.tabs)

        # Add the Home Tab
        self.home_tab = HomeTab(self)
        self.tabs.addTab(self.home_tab, "Home")

        # Apply styles using the specified colors
        self.apply_styles()

    def close_tab(self, index):
        self.tabs.removeTab(index)

    def apply_styles(self):
        self.setStyleSheet("""QMainWindow {
                   background-color: rgb(30, 30, 36);  /* Black background */
               }
               QTabWidget {
                   background-color: rgb(30, 30, 36);  /* Black background */
               }
               QWidget {
                   background-color: rgb(30, 30, 36);  /* Black background */
               }
               QLabel {
                   color: rgb(255, 255, 255);  /* White text */
                   font-size: 16px;
               }
               QLineEdit {
                   background-color: rgb(30, 30, 36);  /* Black background */
                   border: 2px solid rgb(215, 38, 61);  /* Red border */
                   color: rgb(255, 255, 255);  /* White text */
                   border-radius: 10px;
                   padding: 8px;
               }
               QPushButton {
                   background-color: rgb(215, 38, 61);  /* Default red color */
                   color: rgb(255, 255, 255);  /* White button text */
                   border: none;
                   border-radius: 15px;  /* Rounded corners for a modern look */
                   font-size: 14px;
                   padding: 10px;
               }
               QPushButton:hover {
                   background-color: rgb(235, 68, 90);  /* Lighter shade of red on hover */
                   color: rgb(255, 255, 255);  /* White text on hover */
               }
               QPushButton:pressed {
                   background-color: rgb(195, 28, 51);  /* Darker shade on press */
               }
               """)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ScannerGUI()
    window.show()
    sys.exit(app.exec())
