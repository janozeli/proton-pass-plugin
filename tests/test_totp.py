import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))
from totp_gen import TotpError, normalize_totp, totp_at, totp_code

URI8 = "otpauth://totp/rfc?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1"
URI6 = "otpauth://totp/rfc?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=30"


def test_rfc6238_sha1_vectors():
    assert totp_at(URI8, 59) == "94287082"
    assert totp_at(URI8, 1111111109) == "07081804"
    assert totp_at(URI8, 1111111111) == "14050471"
    assert totp_at(URI6, 59) == "287082"


def test_code_waits_when_fewer_than_three_seconds_remain():
    slept = []
    code = totp_code(URI8, now=59, sleep=lambda seconds: slept.append(seconds))
    assert slept == [1.0], slept
    assert code == totp_at(URI8, 60)
    assert code != "94287082"
    assert totp_code(URI8, now=30, sleep=lambda seconds: slept.append(seconds)) == totp_at(URI8, 30)
    assert slept == [1.0]


def test_errors_do_not_include_the_secret():
    marker = "BADSEED1"
    try:
        normalize_totp(seed=marker)
    except TotpError as exc:
        assert str(exc) == "TOTP secret is invalid"
        assert marker not in str(exc)
    else:
        raise AssertionError("invalid seed was accepted")
    try:
        totp_at(f"otpauth://totp/x?secret={marker}", 0)
    except TotpError as exc:
        assert marker not in str(exc)
    else:
        raise AssertionError("invalid otpauth was accepted")


def test_seed_normalizes_to_an_otpauth_uri_and_matches():
    uri = normalize_totp(seed="gezd gnbv gy3t qojq gezd gnbv gy3t qojq")
    assert uri.startswith("otpauth://totp/login?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    assert "BAD" not in uri
    assert totp_at(uri, 59) == "287082"
    try:
        normalize_totp(otpauth_uri=URI6, seed="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    except TotpError:
        pass
    else:
        raise AssertionError("both inputs were accepted")


if __name__ == "__main__":
    tests = [value for name, value in list(globals().items()) if name.startswith("test_")]
    failed = 0
    for test in tests:
        try:
            test()
        except Exception as exc:
            failed += 1
            print(f"FAIL {test.__name__}: {type(exc).__name__}: {exc}")
        else:
            print(f"OK   {test.__name__}")
    if failed:
        raise SystemExit(f"{failed} of {len(tests)} totp tests failed")
    print(f"{len(tests)} totp tests OK")
