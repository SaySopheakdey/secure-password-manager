import time
import json
import os

ATTEMPTS_FILE = "attempts.json"

MAX_FAILED_ATTEMPTS = 5
BASE_BACKOFF_SECONDS = 1
MAX_BACKOFF_SECONDS = 8
LOCKOUT_SECONDS = 300  # 5 minutes


def load_attempts():
    if not os.path.exists(ATTEMPTS_FILE):
        return {"failed": 0, "last": None, "lock_until": None}
    try:
        with open(ATTEMPTS_FILE, "r") as f:
            return json.load(f)
    except:
        return {"failed": 0, "last": None, "lock_until": None}


def save_attempts(attempts):
    with open(ATTEMPTS_FILE, "w") as f:
        json.dump(attempts, f)


def record_failure():
    data = load_attempts()
    now = int(time.time())

    data["failed"] += 1
    data["last"] = now

    if data["failed"] >= MAX_FAILED_ATTEMPTS:
        data["lock_until"] = now + LOCKOUT_SECONDS

    save_attempts(data)


def reset_attempts():
    save_attempts({"failed": 0, "last": None, "lock_until": None})


def check_lockout():
    data = load_attempts()
    now = int(time.time())

    if data["lock_until"] and now < data["lock_until"]:
        return data["lock_until"] - now

    return 0


def calculate_backoff():
    data = load_attempts()
    failed = data.get("failed", 0)
    if failed <= 0:
        return 0
    return min(MAX_BACKOFF_SECONDS, BASE_BACKOFF_SECONDS * (2 ** (failed - 1)))