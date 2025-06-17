from datetime import datetime, timedelta

class BruteforceDetector:
    def __init__(self, time_window_seconds=45, max_attempts=5, target_path="/login.php"):
        """
        Инициализация детектора с параметрами атаки.
        
        Args:
            time_window_seconds (int): Временное окно в секундах для отслеживания.
            max_attempts (int): Количество попыток, считающееся брутфорсом.
            target_path (str): Путь, который является целью атаки (страница входа).
        """
        self.attempts = {}  # Словарь для хранения попыток: {ip: [timestamp1, timestamp2, ...]}
        self.TIME_WINDOW = timedelta(seconds=time_window_seconds)
        self.MAX_ATTEMPTS = max_attempts
        self.TARGET_PATH = target_path
        self.alerted_ips = set() # Храним IP, по которым уже была тревога, чтобы не спамить

    def detect(self, log_entry):
        """
        Анализирует запись лога на предмет брутфорс-атаки.
        Это основной метод, который будет вызываться движком.
        """
        request_str = log_entry.get('request', '')
        # Проверяем, является ли это POST-запросом на нашу целевую страницу 
        if f"POST {self.TARGET_PATH}" not in request_str:
            return None

        ip = log_entry.get('ip')
        if not ip:
            return None
            
        if ip in self.alerted_ips:
            return None

        current_time = datetime.strptime(log_entry['date'][:-6], '%d/%b/%Y:%H:%M:%S')

        if ip not in self.attempts:
            self.attempts[ip] = []
        
        # Добавляем текущую временную метку
        self.attempts[ip].append(current_time)

        # Удаляем старые временные метки, которые вышли за пределы нашего окна
        self.attempts[ip] = [t for t in self.attempts[ip] if current_time - t < self.TIME_WINDOW]
        
        # Если количество попыток в окне превышает порог
        if len(self.attempts[ip]) >= self.MAX_ATTEMPTS:
            self.alerted_ips.add(ip) 
            return f"Обнаружена потенциальная Brute-force атака на {self.TARGET_PATH}. Попыток: {len(self.attempts[ip])}"
            
        return None