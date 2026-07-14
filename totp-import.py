import base64
import hmac
import hashlib
import time
from urllib.parse import urlparse, parse_qs

# 🔹 Full migration URLs
DATA = [
  "otpauth-migration://offline?data=CjwKFFiBlXBIMgFFKmDxWXH00ZXoCrAWEhFhc2xhbUBvdXRsb29rLmNvbRoNVGVzdCBJc3N1ZXIgMSAAKAEKPAoUouJctQ185gRyk8TLiMT4HJuD8N0SEWFzbGFtQG91dGxvb2suY29tGg1UZXN0IElzc3VlciAyIAAoAQgB"
]


# -----------------------------
# Extract base64 data from URL
# -----------------------------
def extract_data(url):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    return query["data"][0]


# -----------------------------
# Minimal protobuf parser
# -----------------------------
def read_varint(buf, i):
    result = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, i


def read_length_delimited(buf, i):
    length, i = read_varint(buf, i)
    val = buf[i:i + length]
    return val, i + length


def parse_payload(buf):
    i = 0
    results = []

    while i < len(buf):
        tag = buf[i]
        i += 1

        field_number = tag >> 3
        wire_type = tag & 0x07

        if wire_type == 2:
            val, i = read_length_delimited(buf, i)

            if field_number == 1:
                results.append(parse_otp(val))

        elif wire_type == 0:
            _, i = read_varint(buf, i)

    return results


def parse_otp(buf):
    i = 0
    otp = {
        "secret": None,
        "name": None,
        "issuer": None,
        "digits": 6
    }

    while i < len(buf):
        tag = buf[i]
        i += 1

        field_number = tag >> 3
        wire_type = tag & 0x07

        if wire_type == 2:
            val, i = read_length_delimited(buf, i)

            if field_number == 1:
                otp["secret"] = val
            elif field_number == 2:
                otp["name"] = val.decode()
            elif field_number == 3:
                otp["issuer"] = val.decode()

        elif wire_type == 0:
            val, i = read_varint(buf, i)

            if field_number == 5:
                if val == 2:
                    otp["digits"] = 8
                else:
                    otp["digits"] = 6

    return otp


# -----------------------------
# TOTP generator
# -----------------------------
def generate_totp(secret, digits=6, interval=30):
    current_time = int(time.time())
    counter = current_time // interval
    remaining = interval - (current_time % interval)

    msg = counter.to_bytes(8, 'big')

    h = hmac.new(secret, msg, hashlib.sha1).digest()

    o = h[-1] & 0x0F
    code = (int.from_bytes(h[o:o + 4], 'big') & 0x7fffffff) % (10 ** digits)

    return str(code).zfill(digits), remaining


# -----------------------------
# Run
# -----------------------------
for url in DATA:
    
    base64_data = extract_data(url)
    raw = base64.b64decode(base64_data)

    accounts = parse_payload(raw)

    for acc in accounts:
        print("Account :", acc["name"])
        print("Issuer  :", acc["issuer"])

        secret_b32 = base64.b32encode(acc["secret"]).decode()
        print("Secret  :", secret_b32)

        otp, remaining = generate_totp(acc["secret"], acc["digits"])
        print("OTP NOW :", otp, f"({remaining}s left)")

        print("-" * 40)
