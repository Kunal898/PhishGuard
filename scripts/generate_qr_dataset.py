import qrcode
import os
import json

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data", "qr_codes")
BENIGN_DIR = os.path.join(DATA_DIR, "benign")
MALICIOUS_DIR = os.path.join(DATA_DIR, "malicious")

os.makedirs(BENIGN_DIR, exist_ok=True)
os.makedirs(MALICIOUS_DIR, exist_ok=True)

# Sample Data to encode
benign_urls = [
    "https://google.com", "https://github.com", "https://stackoverflow.com",
    "https://wikipedia.org", "https://python.org", "https://phishguard-project.io"
]

phishing_urls = [
    "http://bit.ly/secure-login-amazon-v89", "http://login-paypal-verify.xyz",
    "https://microsoft-account-support.tk", "http://urgent-notice.verification-portal9.ga"
]

def generate_qr(url, path, filename):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(os.path.join(path, filename))

print("🚀 Generating QR Dataset...")

# Generate 5 Benign Samples
for i, url in enumerate(benign_urls):
    generate_qr(url, BENIGN_DIR, f"qr_{i}_benign.png")

# Generate 5 Malicious Samples
for i, url in enumerate(phishing_urls):
    generate_qr(url, MALICIOUS_DIR, f"qr_{i}_malicious.png")

print(f"✅ Dataset generated in {DATA_DIR}")
print("   - data/qr_codes/benign/")
print("   - data/qr_codes/malicious/")
