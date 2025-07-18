import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'secure', 'webscr', 'signin']
IP_PATTERN = r'^https?:\/\/(?:\d{1,3}\.){3}\d{1,3}'
LONG_URL_THRESHOLD = 75

def is_phishing(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    if re.match(IP_PATTERN, url):
        return True, "URL uses IP address"

    if len(url) > LONG_URL_THRESHOLD:
        return True, "URL is very long"

    for word in SUSPICIOUS_KEYWORDS:
        if word in url.lower():
            return True, f"Suspicious keyword found: {word}"

    if domain.count('.') > 2:
        return True, "Excessive subdomains"

    return False, "URL appears clean"


url = input("Enter a URL to scan: ")
flagged, reason = is_phishing(url)
print(f"Phishing Detected: {flagged} | Reason: {reason}")
