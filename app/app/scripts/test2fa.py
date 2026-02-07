import pyotp

def generate_totp(secret: str) -> str:
    """Generate a TOTP code for the given secret."""
    totp = pyotp.TOTP(secret)
    return totp.now()

def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code against a secret."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def generate_new_secret() -> str:
    """Generate a new TOTP secret."""
    return pyotp.random_base32()
