import pandas as pd
import random
import re
import json
import os

# Set seed for reproducibility
random.seed(42)

# Suspicious words and patterns
SUSPICIOUS_PHISHING_DOMAINS = [
    "paypal-update.net", "netflix-verify.com", "bankofamerica-security.com",
    "secure-login-portal.net", "chase-alert.org", "apple-id-verify.com",
    "amazn-delivery-support.com", "crypto-airdrop-rewards.com", "irs-tax-refund.org"
]

SAFE_DOMAINS = [
    "google.com", "github.com", "acme-corp.com", "microsoft.com",
    "atlassian.net", "slack.com", "zoom.us", "gmail.com", "yahoo.com"
]

PHISHING_SUBJECTS = [
    "URGENT: Verify your account immediately",
    "Suspicious login attempt detected on your profile",
    "Your account has been temporarily restricted",
    "Update your billing information now to avoid suspension",
    "Action Required: Confirm your identity within 24 hours",
    "Congratulations! You won the $1,000,000 crypto lottery",
    "Invoice #89273 is past due - immediate payment requested",
    "Security Alert: Your password has expired",
    "Important notice regarding your Amazon shipment update",
    "Unlock your subscription - Payment declined"
]

SAFE_SUBJECTS = [
    "Weekly team sync notes",
    "Meeting invitation: Project review on Tuesday",
    "Re: Question about API documentation",
    "Acme Corp Newsletter - June 2026",
    "Your weekly code review summary",
    "Receipt for your subscription renewal",
    "Welcome to the team - onboarding materials inside",
    "Let's grab coffee this Thursday?",
    "Server status update: All systems operational",
    "Feedback request on candidate interview"
]

# Suspect words, urgency cues, links and details for templates
PHISHING_BODIES = [
    "Dear Customer, We detected a suspicious login attempt on your account from an unrecognized device. Please click the link below to verify your identity immediately: http://{domain}/login?token={token}. Failure to confirm your profile within 24 hours will result in permanent account suspension.",
    "URGENT ACTION REQUIRED. Your billing information has expired and your subscription will be cancelled. To prevent service interruption, please update your credit card details immediately: https://{domain}/billing-update. Thank you for your swift attention.",
    "Congratulations! Your email was selected as the grand prize winner of our annual promotional draw. You have won $1,000,000 in Bitcoin. Click here to claim your reward before it expires: http://{ip_address}/claim-prize?id={token}.",
    "Attention: Your account was accessed from IP address 192.168.4.12 in Russia. If this was not you, reset your password now: http://{domain}/reset-pass. Please review your active sessions immediately.",
    "Dear Valued Member, We were unable to process your latest payment. Please verify your payment details by visiting our secure portal: http://{short_url}/pay-update. If you do not resolve this, your account will be closed.",
    "Your package could not be delivered due to incomplete address details. Please update your delivery preferences and pay a re-routing fee of $1.50 at: http://{domain}/postal-alert. Otherwise, your item will be returned to the sender.",
    "TAX REFUND NOTIFICATION: The IRS has identified an outstanding refund of $1,420.50 in your name. To initiate the direct deposit process, visit the portal: http://{domain}/irs-gov-refund. Act quickly as refunds expire.",
    "Security Notification: Your workspace login credentials will expire in 2 hours. Go to your single-sign-on dashboard to sync your account credentials: http://{domain}/sso-login. Failure to sync will lock you out of systems."
]

SAFE_BODIES = [
    "Hi team, Here are the notes from today's weekly sync. We discussed the timeline for the Q3 release and aligned on key deliverables. Let me know if you have any feedback or additions. Talk soon!",
    "Hi there, I wanted to follow up on the API documentation questions we discussed yesterday. I've updated the Swagger files and pushed them to GitHub at https://github.com/acme/project-docs. Let me know if that works for you.",
    "Hi, You are invited to the project kickoff meeting scheduled for Tuesday at 10:00 AM. We will review the client requirements and establish our milestones. The Zoom link is https://zoom.us/j/9876543210. See you there!",
    "Hi, Thanks for signing up for our weekly tech newsletter. In this issue, we explore the latest updates in Python 3.13, Scikit-learn pipelines, and best practices in frontend design. Read the full post on our blog at https://techbytes.dev/blog/pipeline-guide.",
    "Hi, I've reviewed your pull request and left a few comments on the database migration logic. Most of it looks great, just check the indexing on the email column. You can see the review at https://github.com/acme/repo/pull/42.",
    "Hello, Thank you for your purchase. Your payment was processed successfully. You can download your invoice and view your order status in your user profile: https://acme-corp.com/billing/invoice-98273. Best regards, Acme Team.",
    "Hey! Just checking in to see if you are free for coffee or lunch this Thursday around 12:30. Let me know if that time works, or if you prefer another day. Cheers!",
    "Dear applicant, Thank you for taking the time to interview with us yesterday. We really enjoyed learning about your background in machine learning and web development. We will get back to you with next steps by Friday. Best, HR Team."
]

# Random lists of senders
PHISHING_SENDERS = [
    "security-alert@{domain}",
    "support@{domain}",
    "no-reply@{domain}",
    "billing@{domain}",
    "admin@{domain}",
    "claims@{domain}"
]

SAFE_SENDERS = [
    "team-updates@acme-corp.com",
    "notifications@github.com",
    "newsletter@techbytes.dev",
    "billing@acme-corp.com",
    "manager@acme-corp.com",
    "friend@gmail.com",
    "colleague@yahoo.com",
    "support@microsoft.com",
    "calendar-notification@google.com"
]

CUSTOM_DATA_PATH = "custom_emails.json"

def generate_sample_data(num_samples=1200):
    """Generates synthetic phishing and safe emails."""
    data = []
    
    # Half phishing, half safe
    half = num_samples // 2
    
    # Generate Phishing Emails
    for _ in range(half):
        domain = random.choice(SUSPICIOUS_PHISHING_DOMAINS)
        sender = random.choice(PHISHING_SENDERS).format(domain=domain)
        subject = random.choice(PHISHING_SUBJECTS)
        
        # Suspect details
        token = f"{random.randint(100000, 999999)}"
        ip = f"192.{random.randint(10, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}"
        short = random.choice(["bit.ly", "tinyurl.com", "t.co", "is.gd"]) + f"/{random.choice(['x', 'y', 'z'])}{random.randint(100,999)}"
        
        body = random.choice(PHISHING_BODIES).format(domain=domain, token=token, ip_address=ip, short_url=short)
        
        data.append({
            "sender": sender,
            "subject": subject,
            "body": body,
            "label": 1  # 1 = Phishing
        })
        
    # Generate Safe Emails
    for _ in range(half):
        sender = random.choice(SAFE_SENDERS)
        subject = random.choice(SAFE_SUBJECTS)
        body = random.choice(SAFE_BODIES)
        
        data.append({
            "sender": sender,
            "subject": subject,
            "body": body,
            "label": 0  # 0 = Safe
        })
        
    return pd.DataFrame(data)

def load_custom_emails():
    """Loads custom emails added by the user."""
    if os.path.exists(CUSTOM_DATA_PATH):
        try:
            with open(CUSTOM_DATA_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_custom_email(sender, subject, body, label):
    """Saves a single custom email from user training input."""
    emails = load_custom_emails()
    emails.append({
        "sender": sender,
        "subject": subject,
        "body": body,
        "label": int(label)
    })
    with open(CUSTOM_DATA_PATH, "w") as f:
        json.dump(emails, f, indent=4)

def get_full_dataset():
    """Combines synthetic and user-defined emails into a single dataset."""
    df_synthetic = generate_sample_data()
    custom_list = load_custom_emails()
    
    if custom_list:
        df_custom = pd.DataFrame(custom_list)
        # Ensure correct datatypes
        df_custom['label'] = df_custom['label'].astype(int)
        df = pd.concat([df_synthetic, df_custom], ignore_index=True)
    else:
        df = df_synthetic
        
    # Shuffle dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df
