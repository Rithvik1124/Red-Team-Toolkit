import subprocess

def ping_website(url):
    """Ping a website to check if it is reachable."""
    hostname = url.replace("http://", "").replace("https://", "").split('/')[0]
    command = ["ping", "-n", "1", hostname]  # For Windows
    try:
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return response.returncode == 0
    except Exception as e:
        print(f"An error occurred while pinging: {e}")
        return False
