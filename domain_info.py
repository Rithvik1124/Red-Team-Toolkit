# domain_info.py

from whois import whois
import socket
from pycrtsh import Crtsh
import dns.resolver

class DomainInfo:
    def __init__(self, domain):
        self.domain = domain

    def find_dom_info(self):
        try:
            dom_info = whois(self.domain)
            domain_info = {
                "Name": dom_info.domain_name,
                "Registrar": dom_info.registrar,
                "Creation date": dom_info.creation_date,
                "Expiration Date": dom_info.expiration_date,
                "Last updated": dom_info.updated_date,
                "Status": dom_info.status,
                "Servers": dom_info.name_servers
            }
            return domain_info
        except Exception as ex:
            return {"Error": str(ex)}

    def dom_to_ip(self):
        try:
            # Clean the URL to extract the domain
            domain = self.domain

            # Remove the protocol (http:// or https://) and 'www.' if present
            domain = domain.split("//")[-1].split("/")[0]  # Get only the domain part
            if domain.startswith("www."):
                domain = domain[4:]

            # Log the domain being resolved
            print(f"Resolving IP for domain: {domain}")  # Debugging output

            # Resolve the domain name to an IP address
            return socket.gethostbyname(domain)

        except socket.gaierror as e:  # More specific for DNS resolution errors
            return f"DNS resolution error: {str(e)}"
        except Exception as ex:
            return f"Unexpected error: {str(ex)}"

    def subdom(self):
        """Fetch subdomains for the domain using Crtsh."""
        subdomains = set()
        try:
            domain = self.domain

            # Remove the protocol (http:// or https://) and 'www.' if present
            domain = domain.split("//")[-1].split("/")[0]  # Get only the domain part
            if domain.startswith("www."):
                domain = domain[4:]
            # Fetch subdomains from Crtsh
            crtsh_client = Crtsh()
            print(f"Fetching subdomains for: {domain}")
            response = crtsh_client.search(domain)

            for record in response:
                subdomain = record['name']
                if subdomain.endswith(domain):  # Ensure it belongs to the main domain
                    subdomains.add(subdomain)

            print(f"Fetched subdomains for {domain}: {subdomains}")

        except Exception as e:
            print(f"Error while fetching subdomains: {e}")

        return subdomains