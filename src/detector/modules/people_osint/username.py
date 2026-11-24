import re


def validate_username(username):
    username = username.strip()

    if not username:
        return {
            "valid": False,
            "username": username,
            "message": "Username cannot be empty."
        }

    if len(username) < 3 or len(username) > 30:
        return {
            "valid": False,
            "username": username,
            "message": "Username must be 3-30 characters."
        }

    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
        return {
            "valid": False,
            "username": username,
            "message": "Username contains unsupported characters."
        }

    return {
        "valid": True,
        "username": username,
        "message": "Username format is valid."
    }
