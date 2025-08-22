
# ANSI color codes
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def banner_main():
    art = f"""
{GREEN}
  █████████             ██████       ██████   █████           █████   
 ███░░░░░███           ███░░███     ░░██████ ░░███           ░░███    
░███    ░░░  ██████   ░███ ░░░██████ ░███░███ ░███   ██████  ███████  
░░█████████ ░░░░░███ ███████ ███░░███░███░░███░███  ███░░███░░░███░   
 ░░░░░░░░███ ███████░░░███░ ░███████ ░███ ░░██████ ░███████   ░███    
 ███    ░██████░░███  ░███  ░███░░░  ░███  ░░█████ ░███░░░    ░███ ███
░░█████████░░████████ █████ ░░██████ █████  ░░█████░░██████   ░░█████ 
 ░░░░░░░░░  ░░░░░░░░ ░░░░░   ░░░░░░ ░░░░░    ░░░░░  ░░░░░░     ░░░░░  
                                                                                                                                                               
{CYAN}          SafeNet : Cybersecurity Awareness Toolkit{RESET}                                                                         

{YELLOW}A command-line toolkit  designed to test,  train, and  raise  awareness  
about  modern  cybersecurity threats.  Strengthen  your  skills through  
quizzes,    phishing    detection,    password    checks,   and   more.{RESET}
"""
    print(art)


def banner_heading(title: str):
    """
    Display a section heading with a fixed-width SafeNet style.
    The '=' signs are always the same length for consistent look.
    """
    total_width = 70  # Fixed total width for all headings
    side_width = (total_width - len(title) - 2) // 2  # Equal '=' on both sides

    print(f"\n{GREEN}{'=' * total_width}{RESET}")
    print(f"{CYAN}{'=' * side_width} {title} {'=' * side_width}{RESET}")
    print(f"{GREEN}{'=' * total_width}{RESET}")
    print()


def banner_summary(title: str):
    """
    Display a smaller summary banner with fixed-width dashes.
    Works for any title length.
    """
    total_width = 60  # Fixed total width for summary banners
    side_width = (total_width - len(title) - 2) // 2  # Equal '-' on both sides

    print(f"\n{YELLOW}{'-' * side_width} {title} {'-' * side_width}{RESET}")