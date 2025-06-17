# core/analysis_engine.py (новая версия)
from detectors.sqli_detector import detect_sqli
from detectors.xss_detector import detect_xss
from detectors.traversal_detector import detect_traversal
from detectors.bruteforce_detector import BruteforceDetector

class AnalysisEngine:
    def __init__(self, config):
        """
        Инициализируем движок, используя настройки из конфига.
        """
        self.stateless_detectors = []
        
        # Включение детекторов на основе конфига 
        if config.get('sqli_detector', {}).get('enabled', True):
            self.stateless_detectors.append(detect_sqli)
        if config.get('xss_detector', {}).get('enabled', True):
            self.stateless_detectors.append(detect_xss)
        if config.get('traversal_detector', {}).get('enabled', True):
            self.stateless_detectors.append(detect_traversal)
            
        # Настройка stateful детекторы
        if config.get('bruteforce_detector', {}).get('enabled', True):
            brute_config = config['bruteforce_detector']
            self.bruteforce_detector = BruteforceDetector(
                time_window_seconds=brute_config.get('time_window_seconds', 60),
                max_attempts=brute_config.get('max_attempts', 5),
                target_path=brute_config.get('target_path', '/login.php')
            )
        else:
            self.bruteforce_detector = None

        print(f"[*] Движок анализа инициализирован. Stateless-детекторов: {len(self.stateless_detectors)}.")
        if self.bruteforce_detector:
            print("[*] Stateful-детектор (Bruteforce) активен.")

    def run(self, log_entry):
        """
        Прогоняет одну запись лога через все активные детекторы.
        """
        threats_found = []
        
        for detector in self.stateless_detectors:
            result = detector(log_entry)
            if result:
                threats_found.append(result)
        
        if self.bruteforce_detector:
            bruteforce_result = self.bruteforce_detector.detect(log_entry)
            if bruteforce_result:
                threats_found.append(bruteforce_result)
            
        return threats_found