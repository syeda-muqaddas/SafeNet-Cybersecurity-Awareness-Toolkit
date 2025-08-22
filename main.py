# main.py

from breach import is_breached                           # from breach.py
from password import check_password, suggest_password    # from password.py
from phish import detect_phishing                        # from phish.py
from phish import suggest_safe_email, suggest_safe_url   # reuse phish.py suggestion functions

# Main program loop
while True:
    # Show menu to the user
    print("\nChoose an option:")
    print("1. Check Breach (Email/Password/URL)")
    print("2. Check Password Strength")
    print("3. Detect Phishing (Email/URL)")
    print("4. Get Suggestion (Email/Password/URL)")
    print("5. Exit")

    # Take user choice
    choice = input("Enter option (1-5): ")

    # Option 1 → Check breach
    if choice == "1":
        text = input("Enter Email, Password, or URL: ")
        if is_breached(text):   # Call breach.py
            print("⚠️ Found in breach list!")
        else:
            print("✅ Safe: Not found in breaches.")

    # Option 2 → Check password strength
    elif choice == "2":
        password = input("Enter your password: ")
        strength, reasons = check_password(password)  # Call password.py
        print("Strength:", strength)
        if reasons:
            print("Issues:")
            for r in reasons:
                print("-", r)
        print("🔑 Suggested strong password:", suggest_password())

    # Option 3 → Detect phishing
    elif choice == "3":
        text = input("Enter Email or URL: ")
        phishing, reasons, suggestion = detect_phishing(text)  # Call phish.py
        if phishing:
            print("⚠️  Phishing detected!")
            for r in reasons:
                print("-", r)
            if suggestion:
                print("💡 Suggested Safe Example:", suggestion)
        else:
            print("✅ Safe (No phishing detected)")

    # Option 4 → Suggestions
    elif choice == "4":
        print("\nChoose what you want a suggestion for:")
        print("1. Email")
        print("2. Password")
        print("3. URL")
        sub_choice = input("Enter option (1-3): ")

        if sub_choice == "1":
            print("💡 Suggested Safe Email:", suggest_safe_email())
        elif sub_choice == "2":
            print("💡 Suggested Strong Password:", suggest_password())
        elif sub_choice == "3":
            print("💡 Suggested Safe URL:", suggest_safe_url())
        else:
            print("Invalid sub-option.")

    # Option 5 → Exit
    elif choice == "5":
        print("Exiting program... Goodbye!👋 safeNet")
        break

    # Invalid choice
    else:
        print("Invalid option. Please try again.")
