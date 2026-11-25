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
    """Normalize a counter state into a dictionary.

    A state is ``{"counter": int, "used": [int, ...]}``: the current
    (next expected / high-water) counter and the set of counters that have
    already been consumed successfully.
    """
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
    parsed = {
        "counter": int(state.get("counter", 0)),
        "used": [int(value) for value in state.get("used", [])],
    }
    # An optional recorded-set limit is part of the persisted state and
    # must survive normalization.  It is only materialized when supplied so
    # that ordinary states keep their exact counter/used shape.
    if state.get("limit") is not None:
        parsed["limit"] = int(state["limit"])
    return parsed


def candidates(state, window=DEFAULT_WINDOW) -> list:
    """Return candidate counters for a verification attempt.

    Only the current counter and a bounded forward look-ahead window are
    considered.  Counters below the current counter are history and are
    never candidates, so rolled-back / replayed counters cannot match.
    """
    parsed = parse_state(state)
    window = int(window)
    if window < 0:
        raise ValueError("window must not be negative")
    current = int(parsed["counter"])
    return list(range(current, current + window + 1))


def match(code, secret, candidates, digits=DEFAULT_DIGITS) -> int:
    """Return the matching counter, or minus one when absent.

    Codes must match in full and in constant time; a prefix of a code is
    never accepted.
    """
    code = str(code)
    code_bytes = code.encode("utf-8")
    for counter in candidates:
        expected = code_at(secret, int(counter), digits)
        if hmac.compare_digest(expected.encode("utf-8"), code_bytes):
            return int(counter)
    return -1


def consume(state, counter) -> dict:
    """Consume one counter and return the updated state.

    Every counter value is consumed at most once.  Counter rollback and
    re-use of an already consumed counter are rejected explicitly with
    :class:`ValueError`.  On success the counter only moves forward: the
    new current counter is ``counter + 1`` (always strictly greater than
    the previous current counter because callers only reach this point
    with ``counter >= state.counter``).
    """
    parsed = parse_state(state)
    counter = int(counter)
    current = int(parsed["counter"])

    if counter < current:
        raise ValueError(
            f"counter rollback rejected: attempt {counter} is behind "
            f"current counter {current}"
        )

    used = list(parsed["used"])
    if counter in used:
        raise ValueError(
            f"counter {counter} has already been used; replay rejected"
        )

    used.append(counter)
    # Keep the recorded set bounded by the state's configured limit.  The
    # high-water counter already makes every retained value unreachable as
    # a candidate, so dropping the oldest entries cannot enable a replay.
    limit = int(parsed.get("limit", USED_LIMIT))
    if limit >= 0 and len(used) > limit:
        used = used[-limit:] if limit else []

    return {"counter": counter + 1, "used": used}


def check_monotonic(state, counter) -> bool:
    """Check whether an attempt does not roll the counter backwards.

    The current counter itself is allowed (it may still be unused); only
    counters strictly below the current counter are rollbacks.
    """
    parsed = parse_state(state)
    return int(counter) >= int(parsed["counter"])


def validate_state(state) -> list[str]:
    """Return structural problems found in a state."""
    parsed = parse_state(state)
    problems = []
    if parsed["counter"] < 0:
        problems.append("counter must not be negative")
    for used_counter in parsed["used"]:
        if used_counter < 0:
            problems.append("used counter must not be negative")
        if used_counter >= parsed["counter"]:
            problems.append("used counter is not below current counter")
    limit = parsed.get("limit", USED_LIMIT)
    if len(parsed["used"]) > limit:
        problems.append("used counter limit exceeded")
    return problems


def hotp_batch(attempts) -> dict:
    """Validate a batch of attempts and return one result per user.

    Each user owns an independent counter/used state; one user's state can
    never influence another user's verification.  A supplied ``state`` is
    authoritative for that attempt; attempts without one start from that
    user's state earlier in the same batch or from a fresh initial state.
    Accepted attempts return the new, advanced state with the consumed
    counter recorded; rejected attempts are reported explicitly and keep
    their prior state unchanged.
    """
    results = {}
    user_states: dict = {}

    for attempt in attempts:
        user = str(attempt.get("user", ""))
        secret = attempt.get("secret", "")
        code = str(attempt.get("code", ""))
        digits = int(attempt.get("digits", DEFAULT_DIGITS))
        window = int(attempt.get("window", DEFAULT_WINDOW))

        supplied_state = attempt.get("state")
        if supplied_state is not None:
            state = parse_state(supplied_state)
        elif user in user_states:
            state = user_states[user]
        else:
            state = parse_state(None)

        counter = match(code, secret, candidates(state, window), digits)
        if counter < 0:
            user_states[user] = state
            results[user] = {
                "accepted": False,
                "reason": "no matching counter within the look-ahead window",
                "state": state,
            }
            continue

        if not check_monotonic(state, counter):
            user_states[user] = state
            results[user] = {
                "accepted": False,
                "reason": "counter is not monotonic; rollback rejected",
                "state": state,
            }
            continue

        try:
            new_state = consume(state, counter)
        except ValueError as exc:
            user_states[user] = state
            results[user] = {
                "accepted": False,
                "reason": str(exc),
                "state": state,
            }
            continue

        user_states[user] = new_state
        results[user] = {
            "accepted": True,
            "counter": counter,
            "state": new_state,
        }
    return results
