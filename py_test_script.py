import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
import re
from email import message_from_string
from urllib.parse import urlparse

# Define phishing indicators
URGENT_PHRASES = [
    "urgent", "immediate action", "your account will be suspended",
    "verify your identity", "click here"
]
COMMON_ERRORS = ["you're identity", "click hear", "to you verify"]

# Approved domains (safe list)
TRUSTED_DOMAINS = ["paypal.com"]

def analyze_email(email_raw):
    report = {
        "email_type": "legitimate",  # Default label
        "confidence_score": 0,
        "spoofed_sender": None,
        "header_warnings": [],
        "untrusted_links": [],
        "urgent_language_found": [],
        "grammar_issues_found": [],
        "detailed_findings": [],
    }

    msg = message_from_string(email_raw)

    # --- 1. Check spoofed sender ---
    sender = msg.get("From", "")
    domain_match = re.search(r'@([\w.-]+)', sender)
    sender_domain = domain_match.group(1).lower() if domain_match else ""

    if sender_domain and sender_domain not in TRUSTED_DOMAINS:
        report["spoofed_sender"] = f"Sender domain '{sender_domain}' not in trusted domains."
        report["detailed_findings"].append(report["spoofed_sender"])
        report["confidence_score"] += 30  # Weightage

    # --- 2. Header inspection ---
    received_headers = msg.get_all("Received", [])
    for header in received_headers:
        if "unknown" in header.lower() or "suspicious" in header.lower():
            report["header_warnings"].append(header)
            report["detailed_findings"].append("Suspicious header detected.")
            report["confidence_score"] += 10

    # --- 3. Analyze body ---
    body = get_email_body(msg).lower()

    # a. Check for untrusted URLs
    urls = re.findall(r'https?://[^\s]+', body)
    for url in urls:
        domain = urlparse(url).netloc
        if not any(trusted in domain for trusted in TRUSTED_DOMAINS):
            report["untrusted_links"].append(url)
            report["detailed_findings"].append(f"Untrusted URL detected: {url}")
            report["confidence_score"] += 20

    # b. Check for urgency phrases
    for phrase in URGENT_PHRASES:
        if phrase in body:
            report["urgent_language_found"].append(phrase)
            report["detailed_findings"].append(f"Urgent language used: '{phrase}'")
            report["confidence_score"] += 10

    # c. Check for common grammar mistakes
    for error in COMMON_ERRORS:
        if error in body:
            report["grammar_issues_found"].append(error)
            report["detailed_findings"].append(f"Grammar issue detected: '{error}'")
            report["confidence_score"] += 5

    # --- 4. Final classification ---
    if report["confidence_score"] >= 30:
        report["email_type"] = "phishing"
    else:
        report["email_type"] = "legitimate"

    return report

def get_email_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_payload(decode=True).decode(errors="ignore")
    else:
        return msg.get_payload(decode=True).decode(errors="ignore")
    return ""

# Example usage
if __name__ == "__main__":
    with open("phishing_email.txt", "r") as f:
        email_text = f.read()

    report = analyze_email(email_text)

    print("\n========== EMAIL ANALYSIS REPORT ==========")
    print(f"\n📌 Email Classification: {report['email_type'].upper()}")
    print(f"🔒 Confidence Score: {report['confidence_score']}/100")

    if report["spoofed_sender"]:
        print(f"\n⚠️ Spoofed Sender: {report['spoofed_sender']}")

    if report["header_warnings"]:
        print("\n📬 Header Warnings:")
        for header in report["header_warnings"]:
            print(f" - {header}")

    if report["untrusted_links"]:
        print("\n🌐 Untrusted Links Found:")
        for url in report["untrusted_links"]:
            print(f" - {url}")

    if report["urgent_language_found"]:
        print("\n🚨 Urgent Language Used:")
        for phrase in report["urgent_language_found"]:
            print(f" - {phrase}")

    if report["grammar_issues_found"]:
        print("\n✏️ Grammar Issues:")
        for error in report["grammar_issues_found"]:
            print(f" - {error}")

    if report["detailed_findings"]:
        print("\n📝 Summary of Findings:")
        for item in report["detailed_findings"]:
            print(f" - {item}")

    print("===========================================\n")
