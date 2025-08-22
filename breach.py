# breach.py — SafeNet
# This file checks if a given Email, Password, or URL is:
#   → Breached (already leaked / unsafe)
#   → Suspicious (random nonsense, not valid)
#   → Safe (valid but not leaked)

import re  # regular expressions (used for simple email check)

# ------------------------------
# Function: is_breached
# ------------------------------
def is_breached(text: str) -> bool:
    """
    Check if the input (email/password/url) is breached.
    Returns:
      True  → if text is in breached_list (unsafe)
      False → if text is safe or suspicious
    """

    # STEP 1: Create a breached list (sample database)
    # In real projects → this would be very big (millions of records)
    breached_list = [
        # Common weak passwords
        "123456", "password", "qwerty", "abc123", "iloveyou",

        # Example leaked emails
        "test@example.com", "admin@gmail.com", "fake@yahoo.com",

        # Example dangerous URLs
        "http://badsite.com", "https://phishing.com", "http://malicious.net"
    ]

    # STEP 2: Decide what type of input this is
    # → Is it an email? (looks like something@domain.com)
    is_email = re.match(r"^[^@]+@[^@]+\.[^@]+$", text)

    # → Is it a URL? (starts with http:// or https://)
    is_url = text.startswith("http://") or text.startswith("https://")

    # → Is it a password-like string? (at least 6 chars, letters/numbers only)
    is_password_like = (
    len(text) >= 6
    and re.search(r"[A-Z]", text)   # at least one capital letter
    and re.search(r"[a-z]", text)   # at least one small letter
    and re.search(r"[0-9]", text)   # at least one number
    and re.search(r"[^A-Za-z0-9]", text)  # at least one special char
)

    

     # STEP 3: Suspicious Check
     # If input does not look like email, url, or password → it's nonsense
    if not (is_email or is_url or is_password_like):
        print("⚠️ Suspicious Input: Looks like random nonsense.")
        return False   # Still return False, so main.py shows "Safe"

    # STEP 4: Breach Check
    # If input matches something inside breached_list → it's leaked
    if text in breached_list:
        return True

    # STEP 5: Otherwise → it's valid but not leaked → Safe
    return False


# ------------------------------
# TESTING (only runs if you run breach.py directly)
# ------------------------------
if __name__ == "__main__":
    # Try some examples
    samples = ["123456", "helloWorld", "test@example.com", "ifewoeo", "https://good.com"]

    for item in samples:
        result = is_breached(item)
        if result:
            print(item, "→ Breached ❌")
        else:
            print(item, "→ Safe ✅ (or Suspicious if nonsense)")
