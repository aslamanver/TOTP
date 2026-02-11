#!/usr/bin/env python3

import base64
import hmac
import hashlib
import time
import urllib.parse
import os

# ----------------------------
# Convert plain text to Base32
# ----------------------------
def plain_text_to_base32(text):
    return base64.b32encode(text.encode()).decode('utf-8')

# ----------------------------
# Generate secure random secret
# ----------------------------
def generate_secret(length=20):
    random_bytes = os.urandom(length)
    return base64.b32encode(random_bytes).decode('utf-8')

# ----------------------------
# Generate otpauth URL
# ----------------------------
def generate_otpauth_url(secret, account_name, issuer_name):
    params = {
        'secret': secret.replace('=', ''),
        'issuer': issuer_name,
        'algorithm': 'SHA1',
        'digits': 6,
        'period': 30
    }
    return f"otpauth://totp/{urllib.parse.quote(issuer_name)}:{urllib.parse.quote(account_name)}?{urllib.parse.urlencode(params)}"

# ----------------------------
# Generate TOTP
# ----------------------------
def get_totp_token(secret, for_time=None):
    if for_time is None:
        for_time = int(time.time())

    key = base64.b32decode(secret, casefold=True)
    time_counter = int(for_time / 30)
    msg = time_counter.to_bytes(8, 'big')

    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F

    code = ((h[offset] & 0x7f) << 24 |
            (h[offset+1] & 0xff) << 16 |
            (h[offset+2] & 0xff) << 8 |
            (h[offset+3] & 0xff))

    return str(code % 10**6).zfill(6)

# ----------------------------
# Verify TOTP
# ----------------------------
def verify_totp(token, secret, window=1):
    current_time = int(time.time())

    for w in range(-window, window + 1):
        if get_totp_token(secret, current_time + w * 30) == token:
            return True

    return False

# ----------------------------
# MAIN
# ----------------------------
if __name__ == "__main__":

    user_input = input("Enter a secret (leave empty to auto-generate): ").strip()

    if user_input:
        secret = plain_text_to_base32(user_input)
        print("Using your provided secret (converted to Base32).")
    else:
        secret = generate_secret()
        print("Generated secure random secret.")

    print("\nTOTP Secret:", secret)

    url = generate_otpauth_url(secret, "user@example.com", "MyApp")
    print("\nScan this in Google Authenticator:")
    print(url)

    input("\nPress Enter when ready to verify...")

    totp = get_totp_token(secret)
    print("TOTP Token in Google Authenticator App:", totp)

    token = input("Enter 6-digit token: ").strip()

    if verify_totp(token, secret):
        print("✅ Token is valid!")
    else:
        print("❌ Invalid token!")
