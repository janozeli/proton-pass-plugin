"""RFC 6238 TOTP.

Error text from this module never includes a seed. A generated code expires
with its time step and is not a secret.
"""
import base64, hashlib, hmac, re, struct, time
from urllib.parse import parse_qsl, unquote, urlsplit


class TotpError(Exception):
    def __init__(self):
        super().__init__("TOTP secret is invalid")


_ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def decode_secret(text):
    compact = "".join(str(text).split()).upper().rstrip("=")
    if not compact or not re.fullmatch(r"[A-Z2-7]+", compact):
        raise TotpError()
    padded = compact + "=" * ((8 - len(compact) % 8) % 8)
    try:
        raw = base64.b32decode(padded, casefold=True)
    except Exception:
        raise TotpError()
    if not raw:
        raise TotpError()
    return raw


def parse_otpauth(value):
    if not isinstance(value, str):
        raise TotpError()
    text = value.strip()
    if not text.lower().startswith("otpauth:"):
        return {"secret": decode_secret(text), "digits": 6, "period": 30, "algo": hashlib.sha1}
    parts = urlsplit(text)
    if parts.scheme.lower() != "otpauth" or parts.netloc.lower() != "totp":
        raise TotpError()
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    try:
        digits = int(query.get("digits", "6"))
        period = int(query.get("period", "30"))
    except ValueError:
        raise TotpError()
    if digits not in (6, 7, 8) or not 1 <= period <= 300:
        raise TotpError()
    algo = _ALGOS.get(query.get("algorithm", "SHA1").upper())
    if algo is None:
        raise TotpError()
    return {"secret": decode_secret(unquote(query.get("secret", ""))), "digits": digits, "period": period, "algo": algo}


def hotp(secret, counter, digits, algo):
    digest = hmac.new(secret, struct.pack(">Q", counter), algo).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def totp_at(value, now):
    spec = parse_otpauth(value)
    return hotp(spec["secret"], int(now // spec["period"]), spec["digits"], spec["algo"])


def totp_code(value, now=None, sleep=None, min_remaining=3.0, clock=None):
    """Current code. Sleeps until the next step when less than min_remaining seconds are left."""
    spec = parse_otpauth(value)
    clock = clock or time.time
    sleep = sleep or time.sleep
    injected = now is not None
    current = float(now) if injected else float(clock())
    period = spec["period"]
    remaining = period - (current % period)
    if remaining < min_remaining:
        sleep(remaining)
        current = current + remaining if injected else float(clock())
    return hotp(spec["secret"], int(current // period), spec["digits"], spec["algo"])


def normalize_totp(otpauth_uri=None, seed=None):
    if otpauth_uri and seed:
        raise TotpError()
    if otpauth_uri:
        parse_otpauth(otpauth_uri)
        return otpauth_uri.strip()
    if seed:
        canon = base64.b32encode(decode_secret(seed)).decode("ascii").rstrip("=")
        return f"otpauth://totp/login?secret={canon}&digits=6&period=30&algorithm=SHA1"
    raise TotpError()
