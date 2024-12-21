import time
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By

class SQLInjectionTester:
    def __init__(self, url: str, injection_payloads: dict):
        """
        Initialize the SQL Injection Tester with target URL and payloads.

        :param url: The target URL.
        :param injection_payloads: A dictionary of payload types and their payloads.
        """
        self.url = url
        self.injection_payloads = injection_payloads
        self.field_names = []
        self.results = []  # To store results for each payload and field

    def extract_input_field_names(self):
        """
        Extract input field names from the target page's HTML.
        """
        print("[INFO] Extracting input field names from the target page.")
        driver = webdriver.Chrome()
        try:
            driver.get(self.url)
            html_content = driver.page_source.split('<')
            driver.quit()

            html_content_cleaned = [i for i in html_content if 'input' in i]
            self.field_names = [
                x.split('"')[1] for i in html_content_cleaned for x in i.split() if 'name="' in x
            ]
            print(f"[INFO] Found input fields: {self.field_names}")
        except Exception as e:
            print(f"[ERROR] Failed to extract input fields: {e}")
            driver.quit()

    def test_payloads(self):
        """
        Test all SQL injection payloads on the extracted input fields.
        """
        if not self.field_names:
            print("[ERROR] No input fields to test. Ensure you call extract_input_field_names() first.")
            return

        print("[INFO] Testing payloads on the extracted input fields.")
        for name in self.field_names:
            for payload_type, (description, payload) in self.injection_payloads.items():
                driver = webdriver.Chrome()
                try:
                    driver.get(self.url)
                    input_field = driver.find_element(By.NAME, name)
                    input_field.send_keys(payload)
                    input_field.send_keys(Keys.RETURN)
                    time.sleep(10)  # Wait for the page to process the payload

                    html_content = driver.page_source
                    if "login failed" not in html_content.lower() and "logout" in html_content.lower():
                        print(f"[SUCCESS] Payload '{description}' worked for input field: {name}")
                        self.results.append((name, description, "Success"))
                    else:
                        print(f"[INFO] Payload '{description}' did not work for input field: {name}")
                        self.results.append((name, description, "Failed"))
                except Exception as ex:
                    print(f"[ERROR] Exception occurred while testing field '{name}' with payload '{description}': {ex}")
                    self.results.append((name, description, "Error"))
                finally:
                    driver.quit()

