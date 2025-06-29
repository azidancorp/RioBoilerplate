import re
import rio

def get_password_strength(password: str) -> int:
    """
    Calculate the strength of a given password based on various criteria
    and return a score between 0 and 100.
    
    Based on https://www.uic.edu/apps/strong-password/
    
    """
    length = len(password)
    score = 0

    # Additions
    score += length * 4

    # Check for different character types
    upper_case_letters = re.findall(r'[A-Z]', password)
    lower_case_letters = re.findall(r'[a-z]', password)
    numbers = re.findall(r'\d', password)
    symbols = re.findall(r'[\W_]', password)  # Non-alphanumeric characters

    if upper_case_letters:
        score += (length - len(upper_case_letters)) * 2
    if lower_case_letters:
        score += (length - len(lower_case_letters)) * 2
    if numbers:
        score += len(numbers) * 4
    if symbols:
        score += len(symbols) * 6

    # Middle numbers or symbols
    if length > 2:
        middle_chars = password[1:-1]
        middle_numbers_or_symbols = len(re.findall(r'[\d\W_]', middle_chars))
        score += middle_numbers_or_symbols * 2

    # Requirements
    requirements = [
        length >= 12,
        bool(upper_case_letters),
        bool(lower_case_letters),
        bool(numbers),
        bool(symbols),
    ]
    fulfilled_requirements = sum(requirements)
    if fulfilled_requirements >= 3:
        score += fulfilled_requirements * 2

    # Deductions
    if re.match(r'^[a-zA-Z]+$', password):  # Letters only
        score -= length
    if re.match(r'^\d+$', password):  # Numbers only
        score -= length

    # Repeat characters (case insensitive)
    repeat_chars = len(password) - len(set(password.lower()))
    score -= repeat_chars

    # Consecutive uppercase letters
    consecutive_upper = len(re.findall(r'[A-Z]{2,}', password))
    score -= consecutive_upper * 2

    # Consecutive lowercase letters
    consecutive_lower = len(re.findall(r'[a-z]{2,}', password))
    score -= consecutive_lower * 2

    # Consecutive numbers
    consecutive_numbers = len(re.findall(r'\d{2,}', password))
    score -= consecutive_numbers * 2

    # Sequential letters (3+)
    sequential_letters = sum([
        1 for i in range(len(password) - 2)
        if password[i:i+3].isalpha() and
           ord(password[i+1]) == ord(password[i]) + 1 and
           ord(password[i+2]) == ord(password[i]) + 2
    ])
    score -= sequential_letters * 3

    # Sequential numbers (3+)
    sequential_numbers = sum([
        1 for i in range(len(password) - 2)
        if password[i:i+3].isdigit() and
           ord(password[i+1]) == ord(password[i]) + 1 and
           ord(password[i+2]) == ord(password[i]) + 2
    ])
    score -= sequential_numbers * 3

    # Sequential symbols (3+)
    sequential_symbols = sum([
        1 for i in range(len(password) - 2)
        if re.match(r'[\W_]{3}', password[i:i+3]) and
           ord(password[i+1]) == ord(password[i]) + 1 and
           ord(password[i+2]) == ord(password[i]) + 2
    ])
    score -= sequential_symbols * 3

    # Ensure score is within bounds
    score = max(0, min(score, 99))

    return score

def get_password_strength_color(score: int) -> rio.Color:
    """
    Takes a password strength score (0-99) and returns a color between red and
    green.
    """
    score = max(0, min(score, 99))
    red = (99 - score) / 99
    green = score / 99
    return rio.Color.from_rgb(red, green, 0)

def get_password_strength_status(score: int) -> str:
    """
    Returns a descriptive status (very weak, weak, ok, strong, very strong) for a given score.
    """
    if score < 30:
        return 'very weak'
    elif score < 50:
        return 'weak'
    elif score < 70:
        return 'ok'
    elif score < 90:
        return 'strong'
    else:
        return 'very strong'

