import time

import pyotp

def generate_totp(secret: str) -> str:
    """Generate a TOTP code from a secret."""
    totp = pyotp.TOTP(secret)
    return totp.now()

def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code against a secret."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

if __name__ == "__main__":
    # You can paste your secret here
    secret = input("Enter your 2FA secret: ")
    
    while True:
        # Generate current code
        code = generate_totp(secret)
        time_remaining = 30 - (int(time.time()) % 30)
        
        print(f"\nCurrent TOTP code: {code}")
        print(f"Code valid for: {time_remaining} seconds")
        
        # Ask if user wants to verify a code
        test_code = input("\nEnter a code to verify (or press Enter to generate a new code, or 'q' to quit): ")
        
        if test_code.lower() == 'q':
            break
        elif test_code:
            is_valid = verify_totp(secret, test_code)
            print(f"Code {'is valid' if is_valid else 'is NOT valid'}")
        
        if not test_code:
            time.sleep(1)  # Wait 1 second before generating new code
