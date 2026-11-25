"""Public tests for the HOTP counter exercise."""

from hotp.verify import code_at, hotp_batch

SECRET = "12345678901234567890"
WINDOW = 3
DIGITS = 6


def _attempt(secret, counter, state, user="alice"):
    return {
        "user": user,
        "secret": secret,
        "code": code_at(secret, counter, DIGITS),
        "state": state,
        "window": WINDOW,
        "digits": DIGITS,
    }


def test_code_generation_round_trip():
    code = code_at(SECRET, 0, DIGITS)
    assert len(code) == DIGITS
    assert code.isdigit()

    result = hotp_batch(
        [
            {
                "user": "alice",
                "secret": SECRET,
                "code": code,
                "window": WINDOW,
                "digits": DIGITS,
            }
        ]
    )
    assert result["alice"]["accepted"] is True
    assert result["alice"]["state"]["counter"] == 1


def test_current_code_is_accepted():
    result = hotp_batch([_attempt(SECRET, 4, {"counter": 4, "used": []})])
    assert result["alice"]["accepted"] is True
    assert result["alice"]["counter"] == 4


def test_duplicate_code_is_rejected():
    first = hotp_batch([_attempt(SECRET, 6, {"counter": 5, "used": []})])
    assert first["alice"]["accepted"] is True

    second = hotp_batch([_attempt(SECRET, 6, first["alice"]["state"])])
    assert second["alice"]["accepted"] is False


def test_counter_advances_after_success():
    result = hotp_batch([_attempt(SECRET, 6, {"counter": 5, "used": []})])
    assert result["alice"]["accepted"] is True
    assert result["alice"]["state"]["counter"] == 7


def test_batch_users_are_independent():
    other_secret = "bob-secret-0123456789"
    result = hotp_batch(
        [
            {
                "user": "alice",
                "secret": SECRET,
                "code": code_at(SECRET, 0, DIGITS),
                "window": WINDOW,
                "digits": DIGITS,
            },
            {
                "user": "bob",
                "secret": other_secret,
                "code": code_at(other_secret, 0, DIGITS),
                "window": WINDOW,
                "digits": DIGITS,
            },
        ]
    )
    assert result["alice"]["accepted"] is True
    assert result["bob"]["accepted"] is True
    assert result["alice"]["state"]["counter"] == 1
    assert result["bob"]["state"]["counter"] == 1