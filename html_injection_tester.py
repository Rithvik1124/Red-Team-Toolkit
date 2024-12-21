import time
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By


class HtmlInjectionTester:
    """
    HTML Injection Tester Class.
    """

    def __init__(self, url: str):
        """
        Initialize the tester with the target URL.
        :param url: Target URL to test.
        """
        self.url = url
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

    def test_injection(self):
        """
        Perform HTML injection on the extracted fields.
        """
        if not self.field_names:
            print("[ERROR] No input fields found. Please extract them first.")
            return

        injection_payload = "<button onclick=\"alert('HTML INJECTION PASSED');\">Click Me</button>"

        print(f"[INFO] Testing HTML injection with payload: {injection_payload}")
        for field_name in self.field_names:
            try:
                driver = webdriver.Chrome()
                driver.get(self.url)

                input_field = driver.find_element(By.NAME, field_name)
                input_field.send_keys(injection_payload)
                input_field.send_keys(Keys.RETURN)

                time.sleep(3)

                html_content = driver.page_source
                if "alert('HTML INJECTION PASSED');" in html_content:
                    print(f"[SUCCESS] Injection passed in the field: {field_name}")
                    self.results.append((field_name, "Success"))
                else:
                    print(f"[FAILED] Injection failed in the field: {field_name}")
                    self.results.append((field_name, "Failed"))
            except Exception as ex:
                print(f"[ERROR] Exception in field {field_name}: {ex}")
                self.results.append((field_name, "Error"))
            finally:
                driver.quit()
