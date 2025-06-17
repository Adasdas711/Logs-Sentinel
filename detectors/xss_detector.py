
import re
from urllib.parse import unquote

XSS_PATTERNS = [
    r"<script.*?>.*?</script>",
    r"onerror\s*=",
    r"onload\s*=",
    r"javascript:",
    r"data:text/html"
]

def detect_xss(log_entry):
    """
    Принимает разобранную строку лога и ищет в ней XSS-атаки.
    """

    try:
        request_str = unquote(log_entry.get('request', '')).lower()
    except Exception:
        request_str = log_entry.get('request', '').lower()

    for pattern in XSS_PATTERNS:
        if re.search(pattern, request_str):
            return f"Обнаружен потенциальный XSS. Паттерн: '{pattern}'"
    return None