import imaplib

# Replace with your credentials and server settings
IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993
EMAIL_USERNAME = "referral@goldiehealth.com"
EMAIL_PASSWORD = "gxht lhzx wgpv gfjc"  # Use an app password if using Gmail with 2FA

try:
    # Establish IMAP connection
    mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    mail.login(EMAIL_USERNAME, EMAIL_PASSWORD)
    mail.select("inbox")

    print("IMAP connection successful!")
    mail.logout()
except Exception as e:
    print(f"IMAP connection failed: {e}")

