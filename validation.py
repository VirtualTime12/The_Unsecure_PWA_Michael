import html
from datetime import datetime


def is_present(value):
    return value is not None and value.strip() != ""


def is_reasonable_length(value, min, max):
    return min <= len(value) <= max


def valid_password(value):
    has_upper = any(char.isupper() for char in value)
    has_lower = any(char.islower() for char in value)
    has_digit = any(char.isdigit() for char in value)
    has_special = any(char in "@$!%*?&" for char in value)
    return has_upper and has_lower and has_digit and has_special


def safe_chars(value):
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !-@."
    return all(char in allowed for char in value)


def valid_date(date_str):
    try:
        datetime.strptime(date_str, "%d/%m/%Y")
        return True
    except ValueError:
        return False


def sanitise(value):
    return html.escape(value.strip())
