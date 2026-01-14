import html
from datetime import datetime


def is_present(value):
    return value is not None and value.strip() != ""


def is_reasonable_length(value, min, max):
    return min <= len(value) <= max


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
