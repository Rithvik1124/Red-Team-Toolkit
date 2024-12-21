import time
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.common.exceptions import UnexpectedAlertPresentException


class XSSTester:
    """
    Cross-Site Scripting (XSS) Tester Class.
    """

    def __init__(self, url: str):
        """
        Initialize the tester with the target URL.
        :param url: Target URL to test.
        """
        self.url = url
        self.payload = "<script>alert('XSS')</script>"  # Fixed payload
        self.field_names = []
        self.results = []

    def extract_input_fields(self):
        """
        Extract input field names from the target URL.
        """
        print(f"[INFO] Extracting input fields from {self.url}")
        try:
            driver = webdriver.Chrome()
            driver.get(self.url)
            html_content = driver.page_source.split('<')
            driver.quit()

            html_content_cleaned = [i for i in html_content if 'input' in i]
            self.field_names = [
                x.split('"')[1]
                for i in html_content_cleaned
                for x in i.split()
                if 'name="' in x
            ]
            print(f"[INFO] Found input fields: {self.field_names}")
        except Exception as e:
            print(f"[ERROR] Failed to extract input fields: {e}")
            if driver:
                driver.quit()

    def test_xss(self):
        """
        Perform XSS tests on the extracted fields using the fixed payload.
        """
        if not self.field_names:
            print("[ERROR] No input fields found. Please extract them first.")
            return

        print(f"[INFO] Testing XSS with payload: {self.payload}")
        for field_name in self.field_names:
            try:
                driver = webdriver.Chrome()
                driver.get(self.url)

                input_field = driver.find_element(By.NAME, field_name)
                input_field.send_keys(self.payload)
                input_field.send_keys(Keys.RETURN)

                time.sleep(3)

                html_content = driver.page_source
                current_url = driver.current_url
                user_agent = driver.execute_script("return navigator.userAgent;")

                # Analyze the results
                if "alert" in html_content.lower():
                    result = "Payload Triggered"
                elif self.payload in html_content:
                    result = "Payload Reflected"
                elif "XSS" in user_agent:
                    result = "XSS in User-Agent"
                elif current_url != self.url:
                    result = "Redirect Detected"
                else:
                    result = "Payload Failed"

                print(f"[INFO] Field '{field_name}' test result: {result}")
                self.results.append((field_name, result))

            except UnexpectedAlertPresentException:
                print(f"[SUCCESS] Alert triggered for field: {field_name}")
                self.results.append((field_name, "Payload Triggered"))
            except Exception as e:
                print(f"[ERROR] Exception for field {field_name}: {e}")
                self.results.append((field_name, "Error"))
            finally:
                driver.quit()
