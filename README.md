# Pure Python TOTP (Google Authenticator Compatible)

Pure Python implementation of TOTP (Time-Based One-Time Password) compatible with Google Authenticator built without any third-party libraries.

This script demonstrates how Google Authenticator works on the server side by implementing RFC 6238 manually.

[![asciicast](mfa.gif)](https://asciinema.org/a/23YA1AGm9Yj1qZOk)

## Features

- ✅ Generate secure random TOTP secrets
- ✅ Accept custom plain-text secrets (auto-converted to Base32)
- ✅ Generate `otpauth://` URL compatible with Google Authenticator
- ✅ Manual TOTP generation using:
  - HMAC-SHA1
  - 30-second time step
  - Dynamic truncation
- ✅ Token verification with configurable clock drift window
- ✅ No third-party libraries required

## What It Demonstrates

- How TOTP works internally
- How servers verify Google Authenticator tokens
- How shared-secret + time-based OTP systems function
- RFC 6238 compliant implementation

## Usage

1. Run the script.
2. Enter a custom secret or press Enter to auto-generate one.
3. Scan the generated `otpauth://` URL using Google Authenticator.
4. Enter the 6-digit code from the app to verify.

## Technical Details

- Algorithm: HMAC-SHA1
- Digits: 6
- Period: 30 seconds
- Clock tolerance: ±1 time window (configurable)

## Notes

⚠️ For production use:
- Always generate cryptographically secure random secrets.
- Store secrets encrypted at rest.
- Implement rate limiting for verification attempts.

---

Pure Python. Zero dependencies. Fully transparent TOTP implementation.
