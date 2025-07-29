#!/usr/bin/env python3
"""
Improved output formatting functions for malware scanner
"""

import os
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# Color class for better output formatting
class Bcolors:
    Black = '\033[30m'
    Red = '\033[31m'
    Green = '\033[32m'
    Yellow = '\033[33m'
    Blue = '\033[34m'
    Magenta = '\033[35m'
    Cyan = '\033[36m'
    White = '\033[37m'
    Endc = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def improved_scan_file(_f_file_name, check_file_extension, check_file_size, make_hash, hash_exists_in_db, get_create_date, get_modify_date):
    """Improved scan_file function with better output formatting"""
    _scan_result = ''
    if check_file_extension(_f_file_name):
        if check_file_size(_f_file_name):
            scan_file_hash = make_hash(_f_file_name)
            # Only print for infected files to reduce noise
            if hash_exists_in_db(scan_file_hash):
                print(f'{Bcolors.Red}[THREAT DETECTED]{Bcolors.Endc} {os.path.basename(_f_file_name)} | {Bcolors.Yellow}SHA256: {scan_file_hash[:16]}...{Bcolors.Endc}')
                _scan_result = f'{_f_file_name}|{scan_file_hash}|{get_create_date(_f_file_name)}|{get_modify_date(_f_file_name)}'
    return _scan_result

def improved_scan_directory(_scan_path, get_ip_address, get_hostname, create_job_id, get_osver, 
                           scan_file_func, scan_result_logs, EXCLUDE_DIRS, _scan_result_logs_):
    """Improved scan_directory function with better progress display and formatting"""
    _log_ipaddr = get_ip_address()
    _log_hostname = get_hostname()
    _log_scan_id = create_job_id()
    _log_os_ver = get_osver()

    _count_submitted_file = 0
    _count_infected_file = 0
    _total_files = sum([len(files) for r, d, files in os.walk(_scan_path)])

    print(f'{Bcolors.Cyan}📁 Scanning directory: {_scan_path}{Bcolors.Endc}')
    print(f'{Bcolors.White}📊 Total files to scan: {_total_files}{Bcolors.Endc}')
    print(f'{Bcolors.Green}🔍 Starting scan...{Bcolors.Endc}\n')

    _scan_start_time = time.perf_counter()

    with ThreadPoolExecutor(max_workers=50) as executor:
        # Submit a task for each file in the directory
        for subdir, dirs, files in os.walk(_scan_path):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for file in files:
                _f_file_name = os.path.realpath(os.path.join(subdir, file))
                result = [executor.submit(scan_file_func, _f_file_name)]
                for future in as_completed(result):
                    result = future.result()
                    _count_submitted_file += 1
                    
                    # Calculate progress percentage
                    progress = (_count_submitted_file / _total_files) * 100 if _total_files > 0 else 0
                    progress_bar = '█' * int(progress // 2) + '░' * (50 - int(progress // 2))
                    
                    # Show progress with better formatting
                    print(f'\r{Bcolors.Blue}[{progress_bar}]{Bcolors.Endc} {progress:.1f}% | '
                          f'{Bcolors.White}Scanned: {_count_submitted_file}/{_total_files}{Bcolors.Endc} | '
                          f'{Bcolors.Red if _count_infected_file > 0 else Bcolors.Green}Threats: {_count_infected_file}{Bcolors.Endc}', end='', flush=True)
                    
                    if result:
                        _count_infected_file += 1
                        _contents = f'datetime="{datetime.today().strftime("%Y-%m-%d %H:%M:%S")}",scan_id="{_log_scan_id}",os="{_log_os_ver}",' \
                                    f'hostname="{_log_hostname}",ip="{_log_ipaddr}",infected_file="{result.split("|")[0]}",sha256="{result.split("|")[1]}",' \
                                    f'created_at="{result.split("|")[2]}",modified_at="{result.split("|")[3]}"\n'
                        scan_result_logs(_contents)
    
    print('\n')
    
    # Calculate scan duration
    _scan_end_time = time.perf_counter()
    scan_duration = _scan_end_time - _scan_start_time
    
    print(f'\n{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}')
    print(f'{Bcolors.White}🏁 SCAN COMPLETED{Bcolors.Endc}')
    print(f'{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}')
    print(f'{Bcolors.Cyan}📊 Scan Summary:{Bcolors.Endc}')
    print(f'   • Files Scanned: {Bcolors.White}{_count_submitted_file}{Bcolors.Endc}')
    print(f'   • Scan Duration: {Bcolors.White}{scan_duration:.2f} seconds{Bcolors.Endc}')
    print(f'   • Average Speed: {Bcolors.White}{_count_submitted_file/scan_duration:.1f} files/sec{Bcolors.Endc}')
    
    if _count_infected_file >= 1:
        print(f'   • {Bcolors.Red}⚠️  THREATS DETECTED: {_count_infected_file} file(s){Bcolors.Endc}')
        print(f'\n{Bcolors.Yellow}📋 Detailed results saved to: {_scan_result_logs_}{Bcolors.Endc}')
        print(f'{Bcolors.Red}🚨 IMMEDIATE ACTION REQUIRED - Review and quarantine infected files!{Bcolors.Endc}')
    else:
        print(f'   • {Bcolors.Green}✅ No threats detected - System appears clean{Bcolors.Endc}')
        _contents = f'datetime="{datetime.today().strftime("%Y-%m-%d %H:%M:%S")}",scan_id="{_log_scan_id}",os="{_log_os_ver}",' \
                    f'hostname="{_log_hostname}",ip="{_log_ipaddr}",infected_file="None"\n'
        scan_result_logs(_contents)
        print(f'{Bcolors.Green}📋 Clean scan results logged{Bcolors.Endc}')
    
    print(f'{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}\n')

def print_scanner_header(version):
    """Print improved scanner header"""
    print(f'\n{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}')
    print(f'{Bcolors.White}🔧 MALWARE SCANNER INITIALIZATION{Bcolors.Endc}')
    print(f'{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}')

def print_engine_info(engine_date, signature_count):
    """Print improved engine information"""
    print(f'{Bcolors.Cyan}🗄️  Engine Updated: {Bcolors.White}{engine_date}{Bcolors.Endc}')
    print(f'{Bcolors.Cyan}🔍 AV Signatures: {Bcolors.White}{signature_count:,}{Bcolors.Endc}')
    print(f'{Bcolors.Green}✅ Scanner ready - Initiating scan...{Bcolors.Endc}\n')

def print_update_header():
    """Print improved update header"""
    print(f'{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}')
    print(f'{Bcolors.White}🔄 ENGINE UPDATE{Bcolors.Endc}')
    print(f'{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}')
    print(f'{Bcolors.Cyan}📥 Downloading latest malware signatures...{Bcolors.Endc}')

def print_update_complete(engine_date, signature_count):
    """Print update completion message"""
    print(f'{Bcolors.Green}✅ Update completed successfully!{Bcolors.Endc}')
    print(f'{Bcolors.Cyan}🗄️  Engine Updated: {Bcolors.White}{engine_date}{Bcolors.Endc}')
    print(f'{Bcolors.Cyan}🔍 AV Signatures: {Bcolors.White}{signature_count:,}{Bcolors.Endc}')
    print(f'{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}')
