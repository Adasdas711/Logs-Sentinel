SQLI_PATTERNS = [
    r"(\'|\")\s*or\s*(\'|\")\d+\'=\'\d", # ' or '1'='1
    r"union\s+select",
    r"concat\(",
    r"information_schema"
]


import re


def detect_sqli(log_entry):
    """
    Принимает разобранную строку лога (словарь) и ищет в ней SQLi.
    Возвращает описание угрозы или None.
    """
    request_str = log_entry.get('request', '').lower()
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, request_str):
            return f"Обнаружен потенциальный SQLi. Паттерн: '{pattern}'"
    return None


