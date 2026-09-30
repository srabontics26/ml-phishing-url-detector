from urllib.parse import urlparse
import re

def check_url(url):
    score = 0
    reasons = []

    parsed = urlparse(url)

    if parsed.scheme != "https":
        score += 1
        reasons.append("URL does not use HTTPS")

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed.hostname or ""):
        score += 2
        reasons.append("URL uses an IP address")

    if "@" in url:
        score += 2
        reasons.append("URL contains @ symbol")

    if len(url) > 100:
        score += 1
        reasons.append("URL is unusually long")

    suspicious_words = [
        "login", "verify", "account", "secure",
        "update", "password", "confirm"
    ]

    for word in suspicious_words:
        if word in url.lower():
            score += 1
            reasons.append(f"Contains suspicious word: {word}")
            break

    if score >= 3:
        result = "Suspicious"
    else:
        result = "Probably safe"

    return result, score, reasons


url = input("Enter a URL: ")

result, score, reasons = check_url(url)

print("\nResult:", result)
print("Risk score:", score)

if reasons:
    print("\nReasons:")
    for reason in reasons:
        print("-", reason)
