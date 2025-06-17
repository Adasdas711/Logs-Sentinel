from collections import Counter

class ReportGenerator:
    def __init__(self, findings):
        self.findings = findings

    def generate_console_report(self):
        """
        Генерация и вывод отчета в консоль.
        """
        print("\n" + "="*70)
        print(" " * 25 + "АНАЛИТИЧЕСКИЙ ОТЧЕТ LOG SENTINEL")
        print("="*70)

        if not self.findings:
            print("\n[+] Угроз не обнаружено. Все чисто!\n")
            print("="*70)
            return

        total_threats = len(self.findings)
        print(f"\n[!] Всего обнаружено угроз: {total_threats}\n")

        # Группировка по IP
        ip_counter = Counter(f['ip'] for f in self.findings)
        print("--- Сводка по IP-адресам ---")
        for ip, count in ip_counter.most_common():
            print(f"  - {ip}: {count} инцидентов")

        # Групипровка по Типу
        type_counter = Counter(f['threat_type'] for f in self.findings)
        print("\n--- Сводка по типам угроз ---")
        for threat_type, count in type_counter.items():
            print(f"  - {threat_type}: {count} инцидентов")
        
        print("\n--- Детальный список инцидентов ---")
        for finding in self.findings:
            print(f"\n  [!] IP: {finding['ip']} | Тип: {finding['threat_type']}")
            print(f"      Лог: {finding['line'].strip()}")
            
        print("\n" + "="*70)
