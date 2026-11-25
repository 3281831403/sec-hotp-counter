"""HOTP counter validation helpers used by the exercise."""

from __future__ import annotations

import hashlib
import hmac
import struct

DEFAULT_DIGITS = 6
DEFAULT_WINDOW = 5
USED_LIMIT = 128
SKEW_ALLOWANCE = 64


def _secret_bytes(secret) -> bytes:
    if isinstance(secret, bytes):
        return secret
    return str(secret).encode("utf-8")


def code_at(secret, counter, digits=DEFAULT_DIGITS) -> str:
    """Return the HOTP code for a counter."""
    digits = int(digits)
    if digits < 1:
        raise ValueError("digits must be positive")
    counter = int(counter)
    message = struct.pack(">Q", counter)
    digest = hmac.new(_secret_bytes(secret), message, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def parse_state(state) -> dict:
    """Normalize a counter state into a dictionary."""
    if state is None:
        return {"counter": 0, "used": []}
    if isinstance(state, str):
        text = state.strip()
        if not text:
            return {"counter": 0, "used": []}
        if ":" in text:
            head, _, tail = text.partition(":")
            counter = int(head)
            used = [int(piece) for piece in tail.split(",") if piece.strip()]
        else:
            counter = int(text)
            used = []
        return {"counter": counter, "used": used}
    if not isinstance(state, dict):
        raise TypeError("state must be a mapping, string, or None")
    return {
        "counter": int(state.get("counter", 0)),
        "used": [int(value) for value in state.get("used", [])],
    }


def candidates(state, window=DEFAULT_WINDOW) -> list:
    """Return candidate counters for a verification attempt."""
    parsed = parse_state(state)
    window = int(window)
    if window < 0:
        raise ValueError("window must not be negative")
    return list(range(0, parsed["counter"] + window + 1 + SKEW_ALLOWANCE))


def match(code, secret, candidates, digits=DEFAULT_DIGITS) -> int:
    """Return the matching counter, or minus one when absent."""
    code = str(code)
    for counter in candidates:
        expected = code_at(secret, int(counter), digits)
        if expected.startswith(code) or code.startswith(expected):
            return int(counter)
    return -1


def consume(state, counter) -> dict:
    """Consume one counter and return the updated state."""
    parsed = parse_state(state)
    counter = int(counter)
    used = list(parsed["used"])
    return {"counter": counter + 1, "used": used}


def check_monotonic(state, counter) -> bool:
    """Check whether an attempt moves the counter forward."""
    parsed = parse_state(state)
    return parsed["counter"] < int(counter)


def validate_state(state) -> list[str]:
    """Return structural problems found in a state."""
    parsed = parse_state(state)
    problems = []
    for used_counter in parsed["used"]:
        if used_counter >= parsed["counter"]:
            problems.append("used counter is not below current counter")
    limit = parsed.get("limit", USED_LIMIT)
    if len(parsed["used"]) > limit:
        problems.append("used counter limit exceeded")
    return problems


def hotp_batch(attempts) -> dict:
    """Validate a batch of attempts and return one result per user."""
    results = {}
    shared_state = None
    for attempt in attempts:
        user = str(attempt.get("user", ""))
        secret = attempt.get("secret", "")
        code = str(attempt.get("code", ""))
        digits = int(attempt.get("digits", DEFAULT_DIGITS))
        window = int(attempt.get("window", DEFAULT_WINDOW))

        supplied_state = attempt.get("state")
        if supplied_state is not None:
            state = parse_state(supplied_state)
            shared_state = state
        elif shared_state is None:
            state = parse_state({"counter": 0, "used": []})
            shared_state = state
        else:
            state = shared_state

        counter = match(code, secret, candidates(state, window), digits)
        if counter < 0:
            results[user] = {
                "accepted": False,
                "reason": "no matching counter",
                "state": state,
            }
            continue
        if not check_monotonic(state, counter):
            results[user] = {
                "accepted": False,
                "reason": "counter is not monotonic",
                "state": state,
            }
            continue
        try:
            consume(state, counter)
        except ValueError as exc:
            results[user] = {
                "accepted": False,
                "reason": str(exc),
                "state": state,
            }
            continue
        results[user] = {
            "accepted": True,
            "counter": counter,
            "state": state,
        }
    return results