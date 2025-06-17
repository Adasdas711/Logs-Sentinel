import re


LOG_REGEX = re.compile(r'(?P<ip>[\d\.]+) - - \[(?P<date>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\d+) "(?P<referer>.*?)" "(?P<user_agent>.*?)"')


def parse_log_line(line):
    """
    Парсит одну строку лога.
    Возвращает словарь с данными или None, если строка не соответствует формату.
    """
    match = LOG_REGEX.match(line)
    if match:
        return match.groupdict()
    return None


# Пример использования
if __name__ == '__main__':
    test_line = '127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.php?id=1 HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
    parsed = parse_log_line(test_line)
    print(parsed)