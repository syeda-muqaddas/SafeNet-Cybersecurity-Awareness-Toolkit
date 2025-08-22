# password.py — SafeNet
# Goal: Check password strength and suggest a strong one.
# Uses: functions, if/else, loops, strings, operators.

def check_password(password):
    """
    Returns:
      (strength_label: 'Strong' | 'Medium' | 'Weak', reasons: list[str])
    """
    reasons = []
    score = 0  # we add points for each rule passed

    # Rule 1: length
    if len(password) >= 8:
        score += 1
    else:
        reasons.append("Too short: ❌ use at least 8 characters.")

    # Rule 2: number
    has_digit = False
    for ch in password:
        if ch.isdigit():
            has_digit = True
            break
    if has_digit:
        score += 1
    else:
        reasons.append("❌ Add at least one number (0-9).")

    # Rule 3: uppercase
    has_upper = False
    for ch in password:
        if ch.isupper():
            has_upper = True
            break
    if has_upper:
        score += 1
    else:
        reasons.append("❌ Add at least one uppercase letter (A-Z).")

    # Rule 4: lowercase
    has_lower = False
    for ch in password:
        if ch.islower():
            has_lower = True
            break
    if has_lower:
        score += 1
    else:
        reasons.append("❌ Add at least one lowercase letter (a-z).")

    # Rule 5: special
    specials = "~`!@#$%^&*()-_=+[]{}|;:'\",.<>?/"
    has_special = False
    for ch in password:
        if ch in specials:
            has_special = True
            break
    if has_special:
        score += 1
    else:
        reasons.append("❌ Add at least one special character like @ # $ !")

    # label by score
    if score == 5:
        label = "🟢 Strong"
    elif score >= 3:
        label = "🟡 Medium"
    else:
        label = "🔴 Weak"
    return label, reasons


# simple strong password suggestion 
def suggest_password():
    # We keep it easy: Word + special + number + word
    import random
    words = ["Sky", "Mint", "Wolf", "Nova", "Luna", "Aqua", "Pixel","aBc","xyZ","Greet",]
    specials = ["@", "#", "$", "!", "%", "&"]
    w1 = random.choice(words)
    w2 = random.choice(words)
    sp = random.choice(specials)
    num = random.randint(100, 999)
    # Example: Sky@Mint742
    return w1 + sp + w2 + str(num)
