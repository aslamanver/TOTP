import base64
import urllib.parse
import os


# -----------------------------
# Protobuf writer (minimal)
# -----------------------------
def write_varint(value):
    out = bytearray()
    while True:
        bits = value & 0x7F
        value >>= 7
        if value:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            break
    return bytes(out)


def write_field(tag, value):
    return bytes([tag]) + value


def write_length_delimited(field_number, data):
    tag = (field_number << 3) | 2
    return write_field(tag, write_varint(len(data)) + data)


def encode_otp(name, issuer, secret, algo=0):
    msg = bytearray()

    # secret (field 1)
    msg += write_length_delimited(1, secret)

    # name (field 2)
    msg += write_length_delimited(2, name.encode())

    # issuer (field 3)
    msg += write_length_delimited(3, issuer.encode())

    # algorithm (field 4) ← THIS is SHA
    msg += bytes([32]) + write_varint(algo)

    # digits (field 5 → 1 = 6 digits)
    msg += write_field(40, write_varint(1))

    return bytes(msg)


def encode_payload(accounts):
    """
    Wrap into MigrationPayload
    """

    payload = bytearray()

    for acc in accounts:
        otp = encode_otp(
            acc["name"],
            acc["issuer"],
            acc["secret"],
            algo=0,  # 0 = SHA1, 1 = SHA256, 2 = SHA512
        )

        # field 1 = repeated OtpParameters
        payload += write_length_delimited(1, otp)

    # version = 1
    payload += write_field(8, write_varint(1))

    return bytes(payload)


# -----------------------------
# Final exporter
# -----------------------------
def to_migration_url(accounts):
    raw = encode_payload(accounts)
    b64 = base64.b64encode(raw).decode()

    return f"otpauth-migration://offline?data={urllib.parse.quote(b64)}"


# -----------------------------
# Example usage
# -----------------------------
if __name__ == "__main__":
  
    accounts = [
        {
            "name": "aslam@outlook.com",
            "issuer": "Test Issuer 1",
            "secret": os.urandom(20),
        },
        {
            "name": "aslam@outlook.com",
            "issuer": "Test Issuer 2",
            "secret": os.urandom(20),
        },
    ]

    url = to_migration_url(accounts)

    print("\nGenerated Migration URL:\n")
    print(url)
