import re
from urllib.parse import unquote

TRAVERSAL_PATTERN = r"(\.\./|%2e%2e%2f)"

def detect_traversal(log_entry):
    """
    Принимает разобранную строку лога и ищет в ней попытки обхода каталога.
    """
    
    try:
        request_str = unquote(log_entry.get('request', '')).lower()
    except Exception:
        request_str = log_entry.get('request', '').lower()
        
    if re.search(TRAVERSAL_PATTERN, request_str):
        return "Обнаружена потенциальная атака Path Traversal (обход каталога)"
    return None