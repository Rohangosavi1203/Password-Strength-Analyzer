import json
import math
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
COMMON_FILE = BASE_DIR / "common_passwords.json"


def load_common_passwords():
    try:
        with open(COMMON_FILE, "r", encoding="utf-8") as file:
            return set(json.load(file))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def has_sequential_pattern(password, length=4):
    if len(password) < length:
        return False

    for i in range(len(password) - length + 1):
        chunk = password[i:i + length]
        if all(ord(chunk[j + 1]) == ord(chunk[j]) + 1 for j in range(len(chunk) - 1)):
            return True
        if all(ord(chunk[j + 1]) == ord(chunk[j]) - 1 for j in range(len(chunk) - 1)):
            return True
    return False


def has_repeated_characters(password, count=4):
    return bool(re.search(r"(.)\1{" + str(count - 1) + r",}", password))


def calculate_entropy(password):
    if not password:
        return 0.0

    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"\d", password):
        charset += 10
    if re.search(r"[^A-Za-z0-9]", password):
        charset += 33

    if charset == 0:
        return 0.0

    return round(len(password) * math.log2(charset), 1)


def analyze_password(password):
    common = load_common_passwords()

    checks = {
        "length": len(password) >= 12,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "number": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[^A-Za-z0-9]", password)),
        "common": password.lower() not in common,
        "repeated": not has_repeated_characters(password),
        "sequential": not has_sequential_pattern(password),
    }

    score = 0

    if len(password) >= 16:
        score += 30
    elif len(password) >= 12:
        score += 25
    elif len(password) >= 8:
        score += 15
    elif len(password) >= 6:
        score += 5

    for key in ("uppercase", "lowercase", "number", "special"):
        if checks[key]:
            score += 10

    if checks["common"]:
        score += 10
    else:
        score -= 25

    if checks["repeated"]:
        score += 5
    else:
        score -= 10

    if checks["sequential"]:
        score += 5
    else:
        score -= 10

    score = max(0, min(score, 100))

    if score >= 75:
        strength = "STRONG"
    elif score >= 45:
        strength = "MODERATE"
    else:
        strength = "WEAK"

    entropy = calculate_entropy(password)

    tips = []
    if len(password) < 12:
        tips.append("Use at least 12 characters.")
    if not checks["uppercase"] or not checks["lowercase"]:
        tips.append("Use a mix of uppercase and lowercase letters.")
    if not checks["number"]:
        tips.append("Add numbers.")
    if not checks["special"]:
        tips.append("Add special characters.")
    if not checks["common"]:
        tips.append("Avoid common passwords.")
    if not checks["repeated"]:
        tips.append("Avoid repeated characters.")
    if not checks["sequential"]:
        tips.append("Avoid simple sequences such as 1234 or abcd.")
    if not tips:
        tips.append("Use a unique password and never reuse it across accounts.")

    return {
        "score": score,
        "strength": strength,
        "entropy": entropy,
        "checks": checks,
        "tips": tips,
    }
