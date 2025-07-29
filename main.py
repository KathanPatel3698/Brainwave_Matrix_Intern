__author__ = 'https://github.com/HPPAVILLIAN/'
__version__ = '1.0.0'

import os
import sys
import platform
import importlib
import time
import requests
import hashlib
import magic
import argparse
import uuid
# import netifaces
import socket

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from zipfile import ZipFile

importlib.reload(sys)

SCAN_EXTENSIONS = ['.exe', '.dll', '.sys', '.doc', '.docx', '.xls', '.xlsx', '.py', '.xml', '.cfg', '.txt', '.ppt', '.pptx', '.hwp', '.xapk', '.jpg', '.jpeg', '.png']
EXCLUDE_DIRS = ['venv', 'venv2', '.idea', 'lib']

_today_ = datetime.today().strftime('%Y-%m-%d')
_ctime_ = datetime.today().strftime('%Y-%m-%d %H:%M:%S')

#_home_path_ = 'F:/code/pythonProject/malware_hash_scanner3'
_home_path_ = f'{os.getcwd()}'

_engine_zipfile_ = f'{_home_path_}/{_today_}.zip'
_engine_extract_file_ = f'{_home_path_}/engine.db'
_scan_result_logs_ = f'{_home_path_}/output/{_today_}-infected.log'


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


def download_engine():
    _url = 'https://bazaar.abuse.ch/export/txt/sha256/full/'
    _header = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko) '
                             'Chrome/49.0.2623.112 Safari/537.36', 'Connection': 'keep-alive'}
    try:
        with open(_engine_zipfile_, 'wb') as f:
            r = requests.get(_url, headers=_header, stream=True)
            download_file_length = r.headers.get('Content-Length')
            print(f'{Bcolors.Green} Downloading: {_engine_zipfile_} / {(float(download_file_length) / (1024.0 * 1024.0)):.2f} MB {Bcolors.Endc}')

            if download_file_length is None:
                f.write(r.content)
            else:
                dl = 0
                total_length = int(download_file_length)
                start = time.perf_counter()
                for data in r.iter_content(chunk_size=8092):
                    dl += len(data)
                    f.write(data)
                    done = int(100 * dl / total_length)
                    print(f'[{">" * done}{" " * (100 - done)}] {total_length}/{dl} ({done}%) - {(time.perf_counter() - start):.2f} seconds ', end='\r')

        extract_gzip(_engine_zipfile_, _home_path_)

    except Exception as e:
        print(f'{Bcolors.Yellow}- ::Exception:: Func:[{download_engine.__name__}] Line:[{sys.exc_info()[-1].tb_lineno}] [{type(e).__name__}] {e}{Bcolors.Endc}')
    finally:
        r.close()


def extract_gzip(_engine_zipfile_, _home_path_):
    with ZipFile(_engine_zipfile_, 'r') as zipObj:
        file_list = zipObj.infolist()
        for file in file_list:
            if file.filename[-1] == '/':
                continue
            file.filename = os.path.basename(file.filename)
            if file.filename.lower() == 'full_sha256.txt'.lower():
                zipObj.extract(file, _home_path_)
                _update_file = f'{_home_path_}/{file.filename}'

                if os.path.isfile(_engine_extract_file_):
                    os.remove(_engine_extract_file_)

                try:
                    os.rename(_update_file, _engine_extract_file_)
                except OSError as e:
                    print(f'{_update_file} can not be renamed')
                    print(f'{Bcolors.Yellow}- ::Exception:: Func:[{extract_gzip.__name__}] Line:[{sys.exc_info()[-1].tb_lineno}] [{type(e).__name__}] {e}{Bcolors.Endc}')
                    sys.exit(1)

    # Remove Engine zip
    try:
        os.remove(_engine_zipfile_)
    except OSError as e:
        print(f'{_update_file} can not be renamed')
        print(f'{Bcolors.Yellow}- ::Exception:: Func:[{extract_gzip.__name__}] Line:[{sys.exc_info()[-1].tb_lineno}] [{type(e).__name__}] {e}{Bcolors.Endc}')
        sys.exit(1)

    # Check Downloaded File
    if os.path.isfile(_engine_extract_file_):
        with open(_engine_extract_file_, 'rb') as f:
            file_read = f.read()
            file_hash = hashlib.sha256(file_read).hexdigest()
            file_info = f'===> Extracted Size: {int(os.path.getsize(_engine_extract_file_)) / (1024.0 * 1024.0):.2f} MB\n===> Hash(SHA-256) : {file_hash}\n'

            print(f'\n\n{Bcolors.Green}===> Update Success: {_engine_extract_file_} {Bcolors.Endc}')
            print(f'{Bcolors.Green}{file_info}{Bcolors.Endc}')
    else:
        print(f'{Bcolors.Yellow}[-] {_engine_extract_file_} not found. {Bcolors.Endc}')
        sys.exit(1)


def raw_count(filename):
    n = 0
    with open(filename) as f:
        for line in f:
            if not line.startswith('#'):
                n = n + 1
    return n


def get_engine_last_updated_date(filename):
    with open(filename) as f:
        for line in f:
            if 'Last updated' in line:
                line = line.replace('#', '')
                line = line.lstrip().strip('\n')
                line = line.split(' ')
                line = line[2:5]
                line = ' '.join(line)
                #print(line)
                break
    return line


def hash_exists_in_db(check_hash):
    _mode = 'r'
    _n = 0
    with open(_engine_extract_file_, _mode) as database:
        for line in database:
            _n = _n + 1
            if len(line.strip()) != 0:
                if not line.startswith('#'):
                    if str(check_hash) in str(line):
                        return True
    return False


def scan_result_logs(scan_data):
    """Enhanced logging function with JSON format support"""
    import json
    
    _make_output_dir = f'{_home_path_}/output'
    
    # Ensure output directory exists
    if not os.path.exists(_make_output_dir):
        os.makedirs(_make_output_dir)
    
    # JSON log file
    json_log_file = f'{_make_output_dir}/{_today_}-threats.json'
    
    # Read existing JSON data if file exists
    threats = []
    if os.path.exists(json_log_file):
        try:
            with open(json_log_file, 'r', encoding='utf-8') as f:
                threats = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            threats = []
    
    # Add new threat data
    threats.append(scan_data)
    
    # Write updated JSON data
    with open(json_log_file, 'w', encoding='utf-8') as f:
        json.dump(threats, f, indent=2, ensure_ascii=False)
    
    # Also create a structured text log for easy reading
    structured_log_file = f'{_make_output_dir}/{_today_}-threats-structured.log'
    with open(structured_log_file, 'a', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write(f"THREAT DETECTION REPORT\n")
        f.write("=" * 80 + "\n")
        f.write(f"Detection Time    : {scan_data['datetime']}\n")
        f.write(f"Scan ID          : {scan_data['scan_id']}\n")
        f.write(f"System Info      : {scan_data['os']} | {scan_data['hostname']} | {scan_data['ip']}\n")
        f.write(f"Infected File    : {scan_data['infected_file']}\n")
        f.write(f"SHA256 Hash      : {scan_data['sha256']}\n")
        f.write(f"File Created     : {scan_data['created_at']}\n")
        f.write(f"File Modified    : {scan_data['modified_at']}\n")
        f.write("=" * 80 + "\n\n")


def make_hash(_f_file_name):
    _file_hash = ''
    if os.path.isfile(_f_file_name):
        with open(_f_file_name, 'rb') as f:
            filename_read = f.read()
            _file_hash = hashlib.sha256(filename_read).hexdigest()
    return _file_hash


def check_file_extension(_file_name):
    if _file_name.endswith(tuple(SCAN_EXTENSIONS)):
        return True
    else:
        return False


def check_file_size(_f_file_name):
    # 10MB = '10485760'
    _limit = 104857600

    f = os.stat(_f_file_name).st_size
    if f <= _limit:
        return True
    else:
        return False


def get_create_date(_f_file_name):
    if platform.system() == 'Windows':
        _result = os.path.getctime(_f_file_name)
    else:
        _result = os.path.getmtime(_f_file_name)
    return datetime.fromtimestamp(_result).strftime('%Y-%m-%d %H:%M:%S')


def get_modify_date(_f_file_name):
    _result = os.path.getmtime(_f_file_name)
    return datetime.fromtimestamp(_result).strftime('%Y-%m-%d %H:%M:%S')


def get_file_type(_file_name):
    return magic.from_buffer(open(_file_name, 'rb').read(2048))


def get_hostname():
    return platform.node()


def get_osver():
    return platform.system()


def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    s.close()
    return ip_address


# def get_ip_address():
#     gateways = netifaces.gateways()
#     default_gateway = gateways['default'][netifaces.AF_INET]
#     gateway_ip, interface = default_gateway[0], default_gateway[1]
#     iface = netifaces.ifaddresses(interface)
#     local_ip = iface[netifaces.AF_INET][0]['addr']
#     return local_ip


def create_job_id():
    return uuid.uuid4()


def check_engine():
    if os.path.exists(_engine_extract_file_):
        modify_filetime = os.stat(_engine_extract_file_).st_mtime
        today_num_ymd = datetime.today().strftime('%Y%m%d')
        _engine_file_date = datetime.fromtimestamp(modify_filetime).strftime('%Y%m%d')

        if not(int(_engine_file_date) == int(today_num_ymd)):
            _get_download = False
        else:
            _get_download = True

        if not _get_download:
            print(f'{Bcolors.Yellow}- Updating Engine Signatures.{Bcolors.Endc}')
            download_engine()
        else:
            print(f'{Bcolors.Yellow}- Up2date Engine  : ^_^V {Bcolors.Endc}')
    else:
        print(f'{Bcolors.Yellow}- Updating Engine Signatures.{Bcolors.Endc}')
        download_engine()


def scan_file(_f_file_name):
    _scan_result = ''
    if check_file_extension(_f_file_name):
        if check_file_size(_f_file_name):
            scan_file_hash = make_hash(_f_file_name)
            # Only show threat detections to reduce console noise
            if hash_exists_in_db(scan_file_hash):
                print(f'{Bcolors.Red}[THREAT DETECTED]{Bcolors.Endc} {os.path.basename(_f_file_name)} | {Bcolors.Yellow}SHA256: {scan_file_hash[:16]}...{Bcolors.Endc}')
                _scan_result = f'{_f_file_name}|{scan_file_hash}|{get_create_date(_f_file_name)}|{get_modify_date(_f_file_name)}'
    return _scan_result


def scan_directory(_scan_path):
    _log_ipaddr = get_ip_address()
    _log_hostname = get_hostname()
    _log_scan_id = create_job_id()
    _log_os_ver = get_osver()
    _make_output_dir = f'{_home_path_}/output'  # Define the output directory variable

    _count_submitted_file = 0
    _count_infected_file = 0
    _total_files = sum([len(files) for r, d, files in os.walk(_scan_path)])

    # Enhanced scan initialization display
    print(f'{Bcolors.Cyan}📁 Scanning Directory: {_scan_path}{Bcolors.Endc}')
    print(f'{Bcolors.White}📊 Total Files to Scan: {_total_files:,}{Bcolors.Endc}')
    print(f'{Bcolors.Green}🔍 Starting malware scan...{Bcolors.Endc}\n')

    _scan_start_time = time.perf_counter()

    with ThreadPoolExecutor(max_workers=50) as executor:
        # Submit a task for each file in the directory
        for subdir, dirs, files in os.walk(_scan_path):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for file in files:
                _f_file_name = os.path.realpath(os.path.join(subdir, file))
                result = [executor.submit(scan_file, _f_file_name)]
                for future in as_completed(result):
                    result = future.result()
                    _count_submitted_file += 1
                    _scan_duration_time = time.perf_counter() + _scan_start_time
                    
                    # Enhanced progress display with progress bar (for ALL files)
                    progress = (_count_submitted_file / _total_files) * 100 if _total_files > 0 else 0
                    progress_bar = '█' * int(progress // 2) + '░' * (50 - int(progress // 2))
                    
                    print(f'\r{Bcolors.Blue}[{progress_bar}]{Bcolors.Endc} {progress:.1f}% | '
                          f'{Bcolors.White}Scanned: {_count_submitted_file:,}/{_total_files:,}{Bcolors.Endc} | '
                          f'{Bcolors.Red if _count_infected_file > 0 else Bcolors.Green}Threats: {_count_infected_file}{Bcolors.Endc}', end='', flush=True)
                    
                    if result:
                        _count_infected_file += 1
                        
                        # Create structured data for JSON logging
                        threat_data = {
                            "datetime": datetime.today().strftime("%Y-%m-%d %H:%M:%S"),
                            "scan_id": str(_log_scan_id),
                            "os": _log_os_ver,
                            "hostname": _log_hostname,
                            "ip": _log_ipaddr,
                            "infected_file": result.split("|")[0],
                            "sha256": result.split("|")[1],
                            "created_at": result.split("|")[2],
                            "modified_at": result.split("|")[3]
                        }
                        scan_result_logs(threat_data)
    print('\n')
    
    # Calculate scan duration and statistics
    _scan_end_time = time.perf_counter()
    scan_duration = _scan_end_time - _scan_start_time
    scan_speed = _count_submitted_file / scan_duration if scan_duration > 0 else 0
    
    # Enhanced scan completion display
    print(f'\n{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}')
    print(f'{Bcolors.White}🏁 SCAN COMPLETED{Bcolors.Endc}')
    print(f'{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}')
    print(f'{Bcolors.Cyan}📊 Scan Summary:{Bcolors.Endc}')
    print(f'   • Files Scanned: {Bcolors.White}{_count_submitted_file:,}{Bcolors.Endc}')
    print(f'   • Scan Duration: {Bcolors.White}{scan_duration:.2f} seconds{Bcolors.Endc}')
    print(f'   • Average Speed: {Bcolors.White}{scan_speed:.1f} files/sec{Bcolors.Endc}')
    
    if _count_infected_file >= 1:
        print(f'   • {Bcolors.Red}⚠️  THREATS DETECTED: {_count_infected_file} file(s){Bcolors.Endc}')
        print(f'\n{Bcolors.Yellow}📋 Detailed results saved to:{Bcolors.Endc}')
        print(f'   • JSON Format: {Bcolors.White}{_make_output_dir}/{_today_}-threats.json{Bcolors.Endc}')
        print(f'   • Text Format: {Bcolors.White}{_make_output_dir}/{_today_}-threats-structured.log{Bcolors.Endc}')
        print(f'\n{Bcolors.Red}🚨 IMMEDIATE ACTION REQUIRED - Review and quarantine infected files!{Bcolors.Endc}')
    else:
        print(f'   • {Bcolors.Green}✅ No threats detected - System appears clean{Bcolors.Endc}')
        # Log clean scan result in JSON format
        clean_scan_data = {
            "datetime": datetime.today().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_id": str(_log_scan_id),
            "os": _log_os_ver,
            "hostname": _log_hostname,
            "ip": _log_ipaddr,
            "infected_file": "None",
            "sha256": "N/A",
            "created_at": "N/A",
            "modified_at": "N/A"
        }
        # Note: For clean scans, we could create a separate log file
        # scan_result_logs(clean_scan_data)
        print(f'{Bcolors.Green}📋 Clean scan results logged{Bcolors.Endc}')
    
    print(f'{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}\n')


def main():
    print(f'\n')
    print(f'{Bcolors.Green}▌║█║▌│║▌│║▌║▌█║ {Bcolors.Red}Simple Basic Malware Scanner {Bcolors.White}v{__version__}{Bcolors.Green} ▌│║▌║▌│║║▌█║▌║█{Bcolors.Endc}\n')
    opt = argparse.ArgumentParser(description='Simple Basic Malware Scanner')
    opt.add_argument('--path', help='ex) /home/download')
    opt.add_argument('--update', action='store_true', help='AV Engine Update')

    if len(sys.argv) < 1:
        opt.print_help()
        sys.exit(1)
    else:
        options = opt.parse_args()
        print(f'- Run time: {_ctime_}')
        print('- For questions contact github.com/HPPAVILLIAN\t\t')
        print('\n')

        if options.path:
            _scan_path = os.path.abspath(options.path)
            print(f'{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}')
            print(f'{Bcolors.White}🔧 MALWARE SCANNER INITIALIZATION{Bcolors.Endc}')
            print(f'{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}')
            check_engine()
            print(f'{Bcolors.Cyan}🗄️  Engine Updated: {Bcolors.White}{get_engine_last_updated_date(_engine_extract_file_)}{Bcolors.Endc}')
            print(f'{Bcolors.Cyan}🔍 AV Signatures: {Bcolors.White}{raw_count(_engine_extract_file_):,}{Bcolors.Endc}')
            print(f'{Bcolors.Green}✅ Scanner ready - Initiating scan...{Bcolors.Endc}\n')
            scan_directory(_scan_path)

        elif options.update:
            print(f'{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}')
            print(f'{Bcolors.White}🔄 ENGINE UPDATE{Bcolors.Endc}')
            print(f'{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}')
            print(f'{Bcolors.Cyan}📥 Downloading latest malware signatures...{Bcolors.Endc}')
            check_engine()
            print(f'{Bcolors.Green}✅ Update completed successfully!{Bcolors.Endc}')
            print(f'{Bcolors.Cyan}🗄️  Engine Updated: {Bcolors.White}{get_engine_last_updated_date(_engine_extract_file_)}{Bcolors.Endc}')
            print(f'{Bcolors.Cyan}🔍 AV Signatures: {Bcolors.White}{raw_count(_engine_extract_file_):,}{Bcolors.Endc}')
            print(f'{Bcolors.Green}═══════════════════════════════════════════════════════════════{Bcolors.Endc}')
        else:
            opt.print_help()
            sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f'{Bcolors.Yellow}- ::Exception:: Func:[{__name__}] Line:[{sys.exc_info()[-1].tb_lineno}] [{type(e).__name__}] {e}{Bcolors.Endc}')
