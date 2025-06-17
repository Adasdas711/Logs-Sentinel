import sys
import os
import yaml # type: ignore


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(CURRENT_DIR)


from core.log_parser import parse_log_line
from core.analysis_engine import AnalysisEngine
from reporting.report_generator import ReportGenerator

def load_config(config_path='config.yaml'):
    """Загружает конфигурацию из YAML файла."""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[!] ОШИБКА: Файл конфигурации не найден: {config_path}")
        return None
    except yaml.YAMLError as e:
        print(f"[!] ОШИБКА: Некорректный синтаксис в файле конфигурации: {e}")
        return None

def main():
    print("[*] Запуск Log Sentinel...")
    
    config = load_config()
    if not config:
        return

    log_file_path = config['log_source']['file_path']
    print(f"[*] Конфигурация успешно загружена. Целевой файл логов: {log_file_path}")

    engine = AnalysisEngine(config) 
    all_threats_found = []

    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip() or line.startswith('#'):
                    continue

                parsed_log = parse_log_line(line)
                
                if parsed_log:
                    threats = engine.run(parsed_log)
                    
                    if threats:
                        for threat_info in threats:
                            all_threats_found.append({
                                'line_num': line_num,
                                'ip': parsed_log['ip'],
                                'threat_type': threat_info.split(':')[0],
                                'details': threat_info,
                                'line': line
                            })
    except FileNotFoundError:
        print(f"[!] ОШИБКА: Файл не найден по пути: {log_file_path}")
        return
    except Exception as e:
        print(f"[!] Произошла непредвиденная ошибка во время анализа: {e}")
        return

    print("[*] Анализ завершен. Генерация отчета...")
    report_gen = ReportGenerator(all_threats_found)
    report_gen.generate_console_report()

if __name__ == "__main__":
    main()