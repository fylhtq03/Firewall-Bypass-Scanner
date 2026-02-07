#!/usr/bin/env python3
"""
Комплексный сканер фаервола с поддержкой обхода защиты
Исправленная версия с корректной обработкой хоста
"""

import nmap
import sys
import time
import json
import socket
import threading
from datetime import datetime
from tqdm import tqdm
import argparse
import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import shutil

def check_dependencies():
    """Проверка наличия всех необходимых зависимостей"""
    missing_deps = []
    
    # Проверка Python библиотек
    try:
        import nmap
    except ImportError:
        missing_deps.append("python-nmap (pip install python-nmap)")
    
    try:
        from tqdm import tqdm
    except ImportError:
        missing_deps.append("tqdm (pip install tqdm)")
    
    # Проверка наличия nmap в системе
    if shutil.which("nmap") is None:
        missing_deps.append("nmap (установите через пакетный менеджер вашей ОС)")
    
    if missing_deps:
        print("[-] Отсутствуют необходимые зависимости:")
        for dep in missing_deps:
            print(f"    • {dep}")
        print("\n[+] Установите их следующими командами:")
        print("    pip install python-nmap tqdm")
        print("    # И затем установите nmap:")
        print("    # Ubuntu/Debian: sudo apt install nmap")
        print("    # CentOS/RHEL: sudo yum install nmap")
        print("    # macOS: brew install nmap")
        sys.exit(1)
    
    print("[+] Все зависимости удовлетворены\n")
    return True

class FirewallEvasionScanner:
    def __init__(self, target, output_file="firewall_report.json"):
        """
        Инициализация сканера
        """
        self.target = target
        self.output_file = output_file
        self.nm = nmap.PortScanner()
        self.results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "scans": {},
            "summary": {},
            "open_ports": [],
            "filtered_ports": [],
            "vulnerabilities": []
        }
        
        # НАСТРОЙКИ С ПРАВИЛЬНЫМИ ЗНАЧЕНИЯМИ MTU
        self.scan_config = {
            "tcp_ports": "1-100,443,8080,8443",  # Основные TCP порты
            "udp_ports": "53,67,68,123,161",     # Основные UDP порты
            # MTU значения кратные 8
            "mtu_values": [8, 16, 32, 64, 128, 256, 512, 1024, 1492, 1500],
            "fragment_options": [True, False],
            "source_ports": [None, 53, 80, 443, 8080, 65000],
            "timing_options": ["T2", "T3", "T4"],
            "max_workers": 2,
            "scan_timeout": 300  # Таймаут сканирования в секундах
        }
        
        self.total_scans = 0
        self.completed_scans = 0
        self.lock = threading.Lock()
        
    def validate_target(self):
        """Проверка валидности цели"""
        try:
            # Проверка IP адреса
            ipaddress.ip_address(self.target)
            return True
        except ValueError:
            try:
                # Проверка имени хоста
                socket.gethostbyname(self.target)
                return True
            except socket.error:
                return False
    
    def calculate_total_scans(self):
        """Подсчет общего количества сканирований"""
        mtu_count = len(self.scan_config["mtu_values"])
        source_port_count = len(self.scan_config["source_ports"])
        timing_count = len(self.scan_config["timing_options"])
        fragment_count = len(self.scan_config["fragment_options"])
        
        # Основные TCP методы
        tcp_methods = [
            ("SYN Scan", "-sS"),
            ("ACK Scan", "-sA"),
            ("FIN Scan", "-sF"),
            ("NULL Scan", "-sN"),
            ("XMAS Scan", "-sX"),
            ("Window Scan", "-sW"),
            ("Maimon Scan", "-sM"),
        ]
        
        # UDP сканирование
        udp_methods = [("UDP Scan", "-sU")]
        
        total = (len(tcp_methods) + len(udp_methods)) * \
                mtu_count * source_port_count * timing_count * fragment_count
        
        return total
    
    def validate_scan_arguments(self, technique_name, args):
        """Валидация аргументов сканирования перед выполнением"""
        # Проверка на дублирование опций
        if "--mtu" in args and "-f" in args:
            print(f"[!] Предупреждение: Используются и --mtu и -f одновременно для {technique_name}")
            # Убираем -f если есть --mtu
            args = args.replace(" -f", "")
        
        # Проверка значения MTU
        if "--mtu" in args:
            import re
            m = re.search(r'--mtu\s+(\d+)', args)
            if m:
                mtu_value = int(m.group(1))
                if mtu_value <= 0:
                    print(f"[-] Ошибка: MTU должно быть >0 для {technique_name}")
                    return None
                if mtu_value % 8 != 0:
                    print(f"[-] Ошибка: MTU должно быть кратно 8 (получено {mtu_value}) для {technique_name}")
                    # Автокоррекция MTU до ближайшего кратного 8
                    corrected_mtu = (mtu_value // 8) * 8
                    if corrected_mtu < 8:
                        corrected_mtu = 8
                    args = args.replace(f"--mtu {mtu_value}", f"--mtu {corrected_mtu}")
                    print(f"[+] Автокоррекция MTU до {corrected_mtu}")
        
        return args
    
    def scan_with_technique(self, technique_name, technique_args, 
                           mtu=None, fragment=False, 
                           source_port=None, timing="T4",
                           protocol="tcp", port_range=None):
        """
        Выполнение сканирования с заданной техникой и параметрами
        """
        try:
            # Формирование аргументов
            args = technique_args
            
            # Добавление настроек MTU и фрагментации
            if fragment:
                if mtu and mtu % 8 == 0 and mtu > 0:
                    args += f" --mtu {mtu}"
                elif fragment:
                    args += " -f"  # Используем автофрагментацию если MTU некорректно
            
            # Подмена исходного порта
            if source_port:
                args += f" -g {source_port}"
            
            # Управление скоростью
            args += f" -{timing}"
            
            # Указание портов
            if port_range is None:
                if protocol == "tcp":
                    port_range = self.scan_config["tcp_ports"]
                else:
                    port_range = self.scan_config["udp_ports"]
            
            args += f" -p {port_range}"
            
            # Дополнительные опции для обхода фаервола
            args += " --randomize-hosts"
            
            # Для TCP сканирования добавляем дополнительные опции
            if protocol == "tcp" and technique_args not in ["-sU", "-sUV", "-sU -O"]:
                args += " --max-retries 2"
            
            # Валидация аргументов
            args = self.validate_scan_arguments(technique_name, args)
            if args is None:
                return None
            
            print(f"\n[+] Выполняется: {technique_name}")
            print(f"[+] Параметры: {args}")
            print(f"[+] Хост: {self.target}")
            
            # ОСНОВНОЕ ИСПРАВЛЕНИЕ: правильный вызов метода scan
            try:
                # Убедимся, что хост - это строка
                target_str = str(self.target)
                
                # Используем правильный метод с таймаутом через параметры Nmap
                args_with_timeout = f"{args} --host-timeout {self.scan_config['scan_timeout']}s"
                
                # Вызываем scan с правильными параметрами
                scan_result_obj = self.nm.scan(hosts=target_str, arguments=args_with_timeout)
                
            except Exception as scan_error:
                print(f"[-] Ошибка Nmap при сканировании {technique_name}: {str(scan_error)}")
                
                # Попробуем альтернативный метод с subprocess
                try:
                    cmd = ["nmap"] + args_with_timeout.split() + [target_str]
                    print(f"[!] Попытка через subprocess: {' '.join(cmd)}")
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.scan_config['scan_timeout'])
                    
                    # Парсим вывод вручную
                    scan_result = {
                        "technique": technique_name,
                        "arguments": args_with_timeout,
                        "hosts": [{
                            "host": target_str,
                            "state": "up",
                            "protocols": {}
                        }],
                        "timestamp": datetime.now().isoformat(),
                        "raw_output": result.stdout
                    }
                    
                    with self.lock:
                        self.completed_scans += 1
                    
                    return scan_result
                    
                except subprocess.TimeoutExpired:
                    print(f"[-] Таймаут при сканировании {technique_name}")
                    return None
                except Exception as e:
                    print(f"[-] Ошибка subprocess: {str(e)}")
                    return None
            
            # Сбор результатов из успешного сканирования
            scan_result = {
                "technique": technique_name,
                "arguments": args_with_timeout,
                "hosts": [],
                "timestamp": datetime.now().isoformat()
            }
            
            # Извлекаем результаты сканирования
            try:
                # Проверяем, есть ли результаты для целевого хоста
                if target_str in self.nm.all_hosts():
                    host_info = {
                        "host": target_str,
                        "state": self.nm[target_str].state() if hasattr(self.nm[target_str], 'state') else "unknown",
                        "protocols": {}
                    }
                    
                    # Получаем протоколы
                    protocols = []
                    try:
                        protocols = self.nm[target_str].all_protocols()
                    except:
                        pass
                    
                    for proto in protocols:
                        host_info["protocols"][proto] = {}
                        try:
                            ports = self.nm[target_str][proto].keys()
                            for port in ports:
                                port_info = self.nm[target_str][proto][port]
                                host_info["protocols"][proto][port] = dict(port_info)
                                
                                # Сохранение информации об открытых портах
                                if port_info.get('state') == 'open':
                                    with self.lock:
                                        port_exists = False
                                        for p in self.results['open_ports']:
                                            if p['port'] == port and p['protocol'] == proto:
                                                port_exists = True
                                                break
                                        
                                        if not port_exists:
                                            self.results['open_ports'].append({
                                                'port': port,
                                                'protocol': proto,
                                                'service': port_info.get('name', 'unknown'),
                                                'version': port_info.get('version', ''),
                                                'first_detected': datetime.now().isoformat(),
                                                'detected_by': technique_name
                                            })
                                
                                # Фильтрованные порты
                                elif port_info.get('state') == 'filtered':
                                    with self.lock:
                                        port_exists = False
                                        for p in self.results['filtered_ports']:
                                            if p['port'] == port and p['protocol'] == proto:
                                                port_exists = True
                                                break
                                        
                                        if not port_exists:
                                            self.results['filtered_ports'].append({
                                                'port': port,
                                                'protocol': proto,
                                                'reason': 'filtered',
                                                'detected_by': technique_name
                                            })
                        except:
                            continue
                    
                    scan_result["hosts"].append(host_info)
                else:
                    # Если хост не найден в результатах
                    scan_result["hosts"].append({
                        "host": target_str,
                        "state": "no_results",
                        "protocols": {}
                    })
                    
            except Exception as parse_error:
                print(f"[-] Ошибка парсинга результатов для {technique_name}: {str(parse_error)}")
                scan_result["parse_error"] = str(parse_error)
            
            with self.lock:
                self.completed_scans += 1
            
            return scan_result
            
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"[-] Неожиданная ошибка при сканировании {technique_name}: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
    
    def run_tcp_techniques(self, progress_bar=None):
        """Выполнение всех TCP методов сканирования"""
        tcp_techniques = [
            ("TCP SYN Scan", "-sS"),
            ("TCP ACK Scan", "-sA"),
            ("TCP FIN Scan", "-sF"),
            ("TCP NULL Scan", "-sN"),
            ("TCP XMAS Scan", "-sX"),
            ("TCP Window Scan", "-sW"),
            ("TCP Maimon Scan", "-sM"),
        ]
        
        results = []
        
        tasks = []
        
        for technique_name, technique_args in tcp_techniques:
            for fragment in self.scan_config["fragment_options"]:
                for mtu in self.scan_config["mtu_values"]:
                    for source_port in self.scan_config["source_ports"]:
                        for timing in self.scan_config["timing_options"]:
                            tasks.append({
                                'technique_name': technique_name,
                                'technique_args': technique_args,
                                'fragment': fragment,
                                'mtu': mtu,
                                'source_port': source_port,
                                'timing': timing,
                                'protocol': 'tcp'
                            })
        
        print(f"[+] Запланировано TCP задач: {len(tasks)}")
        
        # Многопоточное выполнение
        with ThreadPoolExecutor(max_workers=self.scan_config["max_workers"]) as executor:
            future_to_task = {}
            
            for task in tasks:
                future = executor.submit(
                    self.scan_with_technique,
                    task['technique_name'],
                    task['technique_args'],
                    task['mtu'],
                    task['fragment'],
                    task['source_port'],
                    task['timing'],
                    task['protocol']
                )
                future_to_task[future] = task
            
            for future in as_completed(future_to_task):
                result = future.result()
                if result:
                    results.append(result)
                
                if progress_bar:
                    with self.lock:
                        progress_bar.update(1)
        
        return results
    
    def run_udp_techniques(self, progress_bar=None):
        """Выполнение UDP сканирования"""
        udp_techniques = [("UDP Scan", "-sU")]
        
        results = []
        
        tasks = []
        
        for technique_name, technique_args in udp_techniques:
            for fragment in self.scan_config["fragment_options"]:
                for mtu in self.scan_config["mtu_values"]:
                    for source_port in self.scan_config["source_ports"]:
                        for timing in self.scan_config["timing_options"]:
                            tasks.append({
                                'technique_name': technique_name,
                                'technique_args': technique_args,
                                'fragment': fragment,
                                'mtu': mtu,
                                'source_port': source_port,
                                'timing': timing,
                                'protocol': 'udp'
                            })
        
        print(f"[+] Запланировано UDP задач: {len(tasks)}")
        
        # UDP сканирование медленнее, используем 1 воркер
        with ThreadPoolExecutor(max_workers=1) as executor:
            future_to_task = {}
            
            for task in tasks:
                future = executor.submit(
                    self.scan_with_technique,
                    task['technique_name'],
                    task['technique_args'],
                    task['mtu'],
                    task['fragment'],
                    task['source_port'],
                    task['timing'],
                    task['protocol']
                )
                future_to_task[future] = task
            
            for future in as_completed(future_to_task):
                result = future.result()
                if result:
                    results.append(result)
                
                if progress_bar:
                    with self.lock:
                        progress_bar.update(1)
        
        return results
    
    def perform_advanced_scans(self):
        """Выполнение дополнительных техник сканирования"""
        advanced_scans = []
        
        print("[+] Выполнение дополнительных техник сканирования...")
        
        # Сканирование с разной длиной данных (в байтах)
        for data_length in [0, 32, 64, 128, 256, 512]:
            try:
                args = f"-sS --data-length {data_length} -T4 -p {self.scan_config['tcp_ports']}"
                print(f"[+] Сканирование с длиной данных: {data_length} байт")
                
                # Убедимся, что хост - строка
                target_str = str(self.target)
                self.nm.scan(hosts=target_str, arguments=args)
                
                if target_str in self.nm.all_hosts():
                    advanced_scans.append({
                        "type": "variable_data_length",
                        "data_length": data_length,
                        "results": dict(self.nm[target_str])
                    })
            except Exception as e:
                print(f"[-] Ошибка при сканировании с длиной данных {data_length}: {str(e)}")
        
        # Сканирование с разным TTL
        for ttl in [1, 16, 32, 64, 128, 255]:
            try:
                args = f"-sS --ttl {ttl} -T4 -p 80,443"
                print(f"[+] Сканирование с TTL: {ttl}")
                
                target_str = str(self.target)
                self.nm.scan(hosts=target_str, arguments=args)
                
                if target_str in self.nm.all_hosts():
                    advanced_scans.append({
                        "type": "ttl_manipulation",
                        "ttl": ttl,
                        "results": dict(self.nm[target_str])
                    })
            except Exception as e:
                print(f"[-] Ошибка при сканировании с TTL {ttl}: {str(e)}")
        
        return advanced_scans
    
    def generate_summary(self):
        """Генерация сводки результатов"""
        open_ports = self.results['open_ports']
        filtered_ports = self.results['filtered_ports']
        
        # Анализ уязвимостей
        vulnerabilities = []
        
        # Проверка известных уязвимостей
        port_vulnerabilities = {
            21: ("FTP", "Возможен анонимный доступ или brute-force", "medium"),
            22: ("SSH", "Возможен brute-force, проверьте версию", "medium"),
            23: ("Telnet", "Нешифрованное соединение", "high"),
            25: ("SMTP", "Возможен спам или перебор", "medium"),
            80: ("HTTP", "Проверьте на веб-уязвимости", "low"),
            443: ("HTTPS", "Проверьте сертификаты и конфигурацию", "low"),
            3389: ("RDP", "Возможен brute-force или BlueKeep", "high"),
            5900: ("VNC", "Часто слабые пароли", "high"),
            8080: ("HTTP-Proxy", "Прокси может быть неправильно настроен", "medium"),
            8443: ("HTTPS-Alt", "Альтернативный HTTPS порт", "low")
        }
        
        for port_info in open_ports:
            port = port_info['port']
            if port in port_vulnerabilities:
                service, vuln, risk = port_vulnerabilities[port]
                vulnerabilities.append({
                    "port": port,
                    "service": service,
                    "vulnerability": vuln,
                    "risk": risk,
                    "detected_service": port_info.get('service', 'unknown')
                })
        
        # Анализ эффективности техник
        technique_effectiveness = {}
        for scan_type, scans in self.results['scans'].items():
            if isinstance(scans, list):
                for scan in scans:
                    if scan and 'technique' in scan:
                        tech_name = scan['technique']
                        open_count = 0
                        if 'hosts' in scan:
                            for host in scan['hosts']:
                                if 'protocols' in host:
                                    for proto, ports in host['protocols'].items():
                                        for port_info in ports.values():
                                            if isinstance(port_info, dict) and port_info.get('state') == 'open':
                                                open_count += 1
                        if tech_name not in technique_effectiveness:
                            technique_effectiveness[tech_name] = 0
                        technique_effectiveness[tech_name] += open_count
        
        # Сортировка по эффективности
        sorted_techniques = sorted(technique_effectiveness.items(), 
                                 key=lambda x: x[1], reverse=True)
        
        # Рекомендации
        recommendations = []
        if open_ports:
            recommendations.append({
                "priority": "high",
                "action": "Провести детальный анализ открытых портов",
                "details": f"Обнаружено {len(open_ports)} открытых портов"
            })
        
        if filtered_ports:
            recommendations.append({
                "priority": "medium",
                "action": "Исследовать фильтрованные порты",
                "details": f"{len(filtered_ports)} портов могут быть защищены фаерволом"
            })
        
        if any(p['service'] in ['unknown', ''] for p in open_ports):
            recommendations.append({
                "priority": "medium",
                "action": "Идентифицировать неизвестные сервисы",
                "details": "Неизвестные сервисы требуют дополнительного исследования"
            })
        
        self.results['summary'] = {
            "total_scans": self.completed_scans,
            "total_open_ports": len(open_ports),
            "total_filtered_ports": len(filtered_ports),
            "open_ports_list": [f"{p['protocol']}/{p['port']} ({p['service']})" 
                              for p in open_ports],
            "filtered_ports_list": [f"{p['protocol']}/{p['port']}" 
                                  for p in filtered_ports],
            "most_effective_techniques": sorted_techniques[:5],
            "vulnerabilities_found": vulnerabilities,
            "recommendations": recommendations
        }
        
        return self.results['summary']
    
    def save_report(self):
        """Сохранение отчета в файл"""
        # Сохраняем JSON отчет
        with open(self.output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        # Создаем текстовый отчет
        text_report = f"""
{'='*80}
ОТЧЕТ СКАНИРОВАНИЯ ФАЕРВОЛА
{'='*80}

Цель: {self.target}
Время начала: {self.results['timestamp']}
Завершено сканирований: {self.completed_scans} из {self.total_scans}

{'='*80}
ОТКРЫТЫЕ ПОРТЫ ({len(self.results['open_ports'])})
{'='*80}
"""
        
        if self.results['open_ports']:
            for port_info in sorted(self.results['open_ports'], key=lambda x: x['port']):
                text_report += f"• Порт {port_info['port']}/{port_info['protocol']}\n"
                text_report += f"  Сервис: {port_info.get('service', 'unknown')}\n"
                if port_info.get('version'):
                    text_report += f"  Версия: {port_info['version']}\n"
                text_report += f"  Обнаружен: {port_info.get('first_detected', 'N/A')}\n"
                text_report += f"  Метод: {port_info.get('detected_by', 'N/A')}\n"
                text_report += "\n"
        else:
            text_report += "Открытые порты не обнаружены.\n"
        
        if self.results['filtered_ports']:
            text_report += f"""
{'='*80}
ФИЛЬТРУЕМЫЕ ПОРТЫ ({len(self.results['filtered_ports'])})
{'='*80}
"""
            for port_info in sorted(self.results['filtered_ports'], key=lambda x: x['port']):
                text_report += f"• Порт {port_info['port']}/{port_info['protocol']}\n"
        
        if self.results['vulnerabilities']:
            text_report += f"""
{'='*80}
ВОЗМОЖНЫЕ УЯЗВИМОСТИ
{'='*80}
"""
            for vuln in self.results['vulnerabilities']:
                text_report += f"• [{vuln['risk'].upper()}] {vuln['service']} (порт {vuln['port']})\n"
                text_report += f"  {vuln['vulnerability']}\n"
                if vuln.get('detected_service'):
                    text_report += f"  Обнаруженный сервис: {vuln['detected_service']}\n"
                text_report += "\n"
        
        summary = self.results.get('summary', {})
        if summary:
            text_report += f"""
{'='*80}
СВОДКА
{'='*80}

Самые эффективные техники обхода:
"""
            for technique, count in summary.get('most_effective_techniques', []):
                text_report += f"• {technique}: обнаружил {count} открытых портов\n"
            
            text_report += """
Рекомендации:
"""
            for rec in summary.get('recommendations', []):
                text_report += f"• [{rec['priority'].upper()}] {rec['action']}\n"
                if rec.get('details'):
                    text_report += f"  {rec['details']}\n"
        
        text_report += f"""
{'='*80}
КОНЕЦ ОТЧЕТА
{'='*80}
"""
        
        # Сохранение текстового отчета
        text_file = self.output_file.replace('.json', '.txt')
        with open(text_file, 'w') as f:
            f.write(text_report)
        
        print(f"\n[+] Отчеты сохранены:")
        print(f"    JSON: {self.output_file}")
        print(f"    TXT:  {text_file}")
        
        return text_report
    
    def run(self):
        """Основной метод запуска сканирования"""
        print(f"""
{'#'*80}
#                   СКАНЕР ФАЕРВОЛА С ОБХОДОМ ЗАЩИТЫ                   #
{'#'*80}

Цель: {self.target}
Время начала: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'#'*80}
""")
        
        # Проверка цели
        if not self.validate_target():
            print(f"[-] Неверный целевой хост: {self.target}")
            return False
        
        print("[+] Цель валидна, начинаем сканирование...")
        
        # Подсчет общего количества сканирований
        self.total_scans = self.calculate_total_scans()
        print(f"[+] Всего запланировано сканирований: {self.total_scans}")
        print("[+] Это может занять значительное время...")
        print("[+] Нажмите Ctrl+C для прерывания\n")
        
        try:
            # Создание прогресс-бара
            pbar = tqdm(total=self.total_scans, desc="Сканирование", 
                       unit="scan", ncols=100, 
                       bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")
            
            # Запуск TCP сканирования
            print("\n[+] Запуск TCP сканирования...")
            tcp_results = self.run_tcp_techniques(progress_bar=pbar)
            self.results['scans']['tcp'] = tcp_results
            
            # Запуск UDP сканирования
            print("\n[+] Запуск UDP сканирования...")
            udp_results = self.run_udp_techniques(progress_bar=pbar)
            self.results['scans']['udp'] = udp_results
            
            # Дополнительные сканирования
            print("\n[+] Выполнение дополнительных техник...")
            advanced_scans = self.perform_advanced_scans()
            self.results['scans']['advanced'] = advanced_scans
            
            pbar.close()
            
            # Генерация сводки
            print("\n[+] Генерация отчета...")
            summary = self.generate_summary()
            
            # Сохранение отчета
            report = self.save_report()
            
            # Вывод краткой сводки
            print(f"\n{'#'*80}")
            print("#                          РЕЗУЛЬТАТЫ                           #")
            print(f"{'#'*80}")
            print(f"\nОткрыто портов: {len(self.results['open_ports'])}")
            print(f"Фильтровано портов: {len(self.results['filtered_ports'])}")
            print(f"Найдено возможных уязвимостей: {len(self.results['vulnerabilities'])}")
            print(f"Выполнено сканирований: {self.completed_scans}/{self.total_scans}")
            
            if summary.get('most_effective_techniques'):
                print(f"\nСамые эффективные техники обхода:")
                for technique, count in summary['most_effective_techniques'][:3]:
                    print(f"  • {technique}: {count}")
            
            print(f"\nОтчеты сохранены в файлах:")
            print(f"  • {self.output_file}")
            print(f"  • {self.output_file.replace('.json', '.txt')}")
            print(f"\n{'#'*80}")
            
            return True
            
        except KeyboardInterrupt:
            print("\n\n[!] Сканирование прервано пользователем")
            print("[+] Сохранение частичных результатов...")
            self.save_report()
            return False
        except Exception as e:
            print(f"\n[-] Критическая ошибка: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

def main():
    parser = argparse.ArgumentParser(
        description="Сканер фаервола с техниками обхода защиты",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s 192.168.1.1
  %(prog)s scanme.nmap.org --output custom_report.json
  %(prog)s example.com --quick
        """
    )
    
    parser.add_argument("target", help="Целевой хост или IP")
    parser.add_argument("-o", "--output", default="firewall_report.json",
                       help="Файл для сохранения отчета")
    parser.add_argument("--quick", action="store_true",
                       help="Быстрое сканирование (ограниченный набор)")
    parser.add_argument("--tcp-ports", default="1-100,443,8080,8443",
                       help="Диапазон TCP портов")
    parser.add_argument("--udp-ports", default="53,67,68,123,161",
                       help="Диапазон UDP портов")
    parser.add_argument("--no-udp", action="store_true",
                       help="Пропустить UDP сканирование")
    
    args = parser.parse_args()
    
    # Проверка зависимостей
    check_dependencies()
    
    # Проверка прав
    if os.geteuid() != 0:
        print("[!] Внимание: Для некоторых видов сканирования требуются права root")
        print("[!] Рекомендуется запустить скрипт с sudo")
        response = input("[?] Продолжить без прав root? (y/N): ")
        if response.lower() != 'y':
            print("[-] Завершение работы")
            sys.exit(1)
    
    # Создание сканера
    scanner = FirewallEvasionScanner(args.target, args.output)
    
    # Настройка для быстрого сканирования
    if args.quick:
        print("[+] Режим быстрого сканирования")
        scanner.scan_config.update({
            "tcp_ports": args.tcp_ports,
            "udp_ports": args.udp_ports,
            "mtu_values": [8, 512, 1500],  # Только несколько значений
            "source_ports": [None, 80, 443],
            "timing_options": ["T3", "T4"],
            "max_workers": 2,
            "scan_timeout": 180  # Уменьшенный таймаут для быстрого сканирования
        })
    else:
        # Использовать порты из аргументов
        scanner.scan_config["tcp_ports"] = args.tcp_ports
        scanner.scan_config["udp_ports"] = args.udp_ports
    
    if args.no_udp:
        scanner.scan_config["udp_ports"] = ""
        print("[+] UDP сканирование отключено")
    
    # Запуск сканирования
    success = scanner.run()
    
    if success:
        print("\n[+] Сканирование успешно завершено!")
        sys.exit(0)
    else:
        print("\n[-] Сканирование завершено с ошибками")
        sys.exit(1)

if __name__ == "__main__":
    main()