# phish.py  — SafeNet 
# Goal: Check if an input looks like a real email or URL.
# Uses: lists, loops, strings, if/else, functions.
# Extra Feature: Suggest safe example email/URL if input is suspicious

import random

# 1) Suspicious keywords list (words that often appear in phishing emails/URLs)
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "account", "update",
    "click here", "password", "bank", "login"
]

# 2) Suspicious parts (strange tokens often found in fake sites)
SUSPICIOUS_PARTS = [
    "http://", "paypa1", "xn--", "//verify", "@@", "verify-account"
]

# ---------- helpers ----------
def is_valid_email(text):
    """Check if text looks like an email: user@domain.tld""" #tld :top level domain
    t = text.strip().lower()# strip: Removes extra spaces or unwanted characters from start and end of a string.
    if t.count("@") != 1:  # must have exactly one "@"
        return False
    user, domain = t.split("@") #split: Breaks a string into parts using a separator.
    if not user or not domain:  # user and domain must not be empty
        return False
    if "." not in domain:  # domain must have at least one "."
        return False
    if domain.startswith(".") or domain.endswith("."):  # cannot start or end with "."
        return False
    allowed_user = "abcdefghijklmnopqrstuvwxyz0123456789._-"
    for ch in user:  # username only valid characters
        if ch not in allowed_user:
            return False
    for part in domain.split("."):  # each part of domain must not be empty
        if not part:
            return False
    return True


def is_valid_url(text):
    """Check if text looks like a URL: http(s)://host..."""
    t = text.strip().lower()
    if not (t.startswith("https://") or t.startswith("http://")):
        return False
    # Remove http(s):// part
    body = t[len("https://"):] if t.startswith("https://") else t[len("http://"):]
    if "." not in body:  # must have a dot after protocol
        return False
    host = body.split("/")[0]
    if not host or host.startswith(".") or host.endswith("."):
        return False
    return True


# ---------- suggestion helpers ----------
def suggest_safe_email():
    """Return a safe example email for user reference"""
    safe_emails = [
        "support123@gmail.com",
        "contact456@gmail.com",
        "info908@example.com",
        "helpdesk156@gmail.com",
        "service842@gmail.com",
        "nava852@gmail.com",
    ]
    return random.choice(safe_emails)


def suggest_safe_url():
    """Return a safe example URL for user reference"""
    safe_urls = [
        "https://www.example.com",
        "https://secure.mybank.com",
        "https://en.wikipedia.org",
        "https://portal.govt.pk",
        "https://contact.cyber.net"
    ]
    return random.choice(safe_urls)


# ---------- main detector ----------
def detect_phishing(text):
    """
    Returns:
      (is_suspicious: bool, reasons: list[str], suggestion: str)
    """
    reasons = []
    t = text.strip().lower()

    # A) basic format check
    is_email = is_valid_email(t)
    is_url = is_valid_url(t)
    if not is_email and not is_url:
        reasons.append("Format check failed: ❌ not a valid email or URL.")

    # B) http instead of https = risky
    if "http://" in t:
        reasons.append("❌ Uses HTTP instead of HTTPS.")

    # C) contains phishing keywords
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in t:
            reasons.append(f"❌ Contains suspicious keyword: '{kw}'.")

    # D) contains suspicious tokens
    for part in SUSPICIOUS_PARTS:
        if part in t:
            reasons.append(f"❌ Contains suspicious token: '{part}'.")

    # E) too many digits (e.g. paypal12345678.com)
    digits = sum(1 for ch in t if ch.isdigit())
    if digits > 6:
        reasons.append("Contains many digits (possible obfuscation).")

    # --- Final decision ---
    is_suspicious = True
    if (is_email or is_url) and len(reasons) == 0:
        is_suspicious = False

    # --- Suggestion (new) ---
    suggestion = None
    if is_suspicious:  # if suspicious, give safe example
        if "@" in t:  # looks like email but wrong
            suggestion = f"Example of safe email: {suggest_safe_email()}"
        elif t.startswith("http://") or t.startswith("https://"):
            suggestion = f"Example of safe URL: {suggest_safe_url()}"
        else:  # neither email nor URL
            suggestion = f"Try format like: {suggest_safe_email()} or {suggest_safe_url()}"

    # Return result
    return is_suspicious, reasons, suggestion
