import socket
import sys
import os
import platform
import importlib
import time
import uuid
import requests
import hashlib
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QScrollArea, QTextEdit, QLabel, QProgressBar, QMessageBox
from PyQt6.QtCore import Qt
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from zipfile import ZipFile

SCAN_EXTENSIONS = ['.exe', '.dll', '.sys', '.doc', '.docx', '.xls', '.xlsx', '.py', '.xml', '.cfg', '.txt', '.ppt', '.pptx', '.hwp', '.xapk', '.jpg', '.jpeg', '.png', '.bat', '.cmd', '.com', '.cpl', '.msi', '.scr', '.vbs', '.js', '.jse', '.wsf', '.lnk', '.zip', '.rar', '.7z', '.tar', '.gz']
EXCLUDE_DIRS = ['venv', 'venv2', '.idea', 'lib']

_today_ = datetime.today().strftime('%Y-%m-%d')
_ctime_ = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
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

class MalwareScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Malware Scanner")
        self.setGeometry(300, 300, 600, 400)

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.scanButton = QPushButton("Scan Files")
        self.scanButton.clicked.connect(self.scan)
        self.layout.addWidget(self.scanButton)

        self.updateButton = QPushButton("Update Engine")
        self.updateButton.clicked.connect(self.update_engine)
        self.layout.addWidget(self.updateButton)

        self.progressBar = QProgressBar()
        self.layout.addWidget(self.progressBar)

        self.logLabel = QLabel("Logs:")
        self.layout.addWidget(self.logLabel)

        self.textEdit = QTextEdit()
        self.textEdit.setReadOnly(True)
        self.layout.addWidget(self.textEdit)

        self.scrollArea = QScrollArea()
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setWidget(self.textEdit)
        self.layout.addWidget(self.scrollArea)

    def log_message(self, message, color=None):
        if color:
            message = f"<span style='color:{color}'>{message}</span>"
        self.textEdit.append(message)
        self.textEdit.ensureCursorVisible()
    
    def get_create_date(self, _f_file_name):
        if platform.system() == 'Windows':
            _result = os.path.getctime(_f_file_name)
        else:
            _result = os.path.getmtime(_f_file_name)
        return datetime.fromtimestamp(_result).strftime('%Y-%m-%d %H:%M:%S')

    def get_modify_date(self, _f_file_name):
        _result = os.path.getmtime(_f_file_name)
        return datetime.fromtimestamp(_result).strftime('%Y-%m-%d %H:%M:%S')

    def get_hostname(self):
        return platform.node()


    def get_osver(self):
        return platform.system()

    def get_ip_address(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    
    def create_job_id(self):
        return uuid.uuid4()

    def scan(self):
        dialog = QFileDialog(self)
        dialog.setFileMode(QFileDialog.FileMode.Directory)
        dialog.setViewMode(QFileDialog.ViewMode.Detail)
        if dialog.exec():
            selectedPath = dialog.selectedFiles()[0]
            self.log_message(f"Scanning {selectedPath}\n")
            self.check_engine()
            self.scan_directory(selectedPath)

    def update_engine(self):
        self.log_message("Updating Engine\n")
        self.download_engine()

    def check_engine(self):
        if os.path.exists(_engine_extract_file_):
            modify_filetime = os.stat(_engine_extract_file_).st_mtime
            today_num_ymd = datetime.today().strftime('%Y%m%d')
            _engine_file_date = datetime.fromtimestamp(modify_filetime).strftime('%Y%m%d')

            if not(int(_engine_file_date) == int(today_num_ymd)):
                _get_download = False
            else:
                _get_download = True

            if not _get_download:
                self.log_message(f"- Updating Engine Signatures.\n")
                self.download_engine()
            else:
                self.log_message(f"- Up2date Engine  : ^_^V\n")
        else:
            self.log_message(f"- Updating Engine Signatures.\n")
            self.download_engine()

    def download_engine(self):
        _url = 'https://bazaar.abuse.ch/export/txt/sha256/full/'
        _header = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko) '
                                 'Chrome/49.0.2623.112 Safari/537.36', 'Connection': 'keep-alive'}
        try:
            with open(_engine_zipfile_, 'wb') as f:
                r = requests.get(_url, headers=_header, stream=True)
                download_file_length = r.headers.get('Content-Length')
                if download_file_length is not None:
                    total_length = int(download_file_length)
                    self.progressBar.setMaximum(total_length)
                    dl = 0
                    for data in r.iter_content(chunk_size=8092):
                        dl += len(data)
                        f.write(data)
                        self.progressBar.setValue(dl)
                    self.log_message(f"Download Complete\n")
                else:
                    f.write(r.content)
                self.progressBar.setValue(self.progressBar.maximum())

            if os.path.isfile(_engine_zipfile_):
                self.extract_gzip(_engine_zipfile_, _home_path_)
                self.log_message(f"Extract Complete\n")
            else:
                self.log_message(f"Error: {_engine_zipfile_} not found\n")

        except Exception as e:
            self.log_message(f"Error: {e}\n")

    def extract_gzip(self, _engine_zipfile_, _home_path_):
        try:
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
                            self.log_message(f"Removing old {_engine_extract_file_}\n")
                            os.remove(_engine_extract_file_)

                        try:
                            self.log_message(f"Renaming {_update_file} to {_engine_extract_file_}\n")
                            os.rename(_update_file, _engine_extract_file_)
                        except OSError as e:
                            self.log_message(f"Error: {_update_file} can not be renamed - {e}\n")
                            QMessageBox.critical(self, "Error", f"{_update_file} can not be renamed - {e}")
                            return

            self.log_message(f"Removing {_engine_zipfile_}\n")
            try:
                os.remove(_engine_zipfile_)
            except OSError as e:
                self.log_message(f"Error: {_engine_zipfile_} can not be removed - {e}\n")
                QMessageBox.critical(self, "Error", f"{_engine_zipfile_} can not be removed - {e}")
                return

            if os.path.isfile(_engine_extract_file_):
                with open(_engine_extract_file_, 'rb') as f:
                    file_read = f.read()
                    file_hash = hashlib.sha256(file_read).hexdigest()
                    file_info = f'===> Extracted Size: {int(os.path.getsize(_engine_extract_file_)) / (1024.0 * 1024.0):.2f} MB\n===> Hash(SHA-256) : {file_hash}\n'

                    self.log_message(f'\n\n{Bcolors.Green}===> Update Success: {_engine_extract_file_} {Bcolors.Endc}')
                    self.log_message(f'{Bcolors.Green}{file_info}{Bcolors.Endc}')
            else:
                self.log_message(f'{Bcolors.Yellow}[-] {_engine_extract_file_} not found. {Bcolors.Endc}')
                QMessageBox.critical(self, "Error", f"{_engine_extract_file_} not found.")
        except Exception as e:
            self.log_message(f"Error: {e}\n")
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")

    def scan_directory(self, root_dir):
        _log_ipaddr = self.get_ip_address()
        _log_hostname = self.get_hostname()
        _log_scan_id = self.create_job_id()
        _log_os_ver = self.get_osver()

        _count_submitted_file = 0
        _count_infected_file = 0

        _scan_start_time = time.perf_counter()

        try:
            self.log_message(f"Scanning Directory: {root_dir}\n")
            for root, dirs, files in os.walk(root_dir):
                for directory in dirs:
                    if directory in EXCLUDE_DIRS:
                        self.log_message(f"Skipping: {os.path.join(root, directory)}\n")
                        dirs.remove(directory)
                        continue
                for file in files:
                    _f_file_name = os.path.realpath(os.path.join(root, file))
                    if os.path.splitext(file)[1].lower() not in SCAN_EXTENSIONS:
                        self.log_message(f"Skipping: {os.path.join(root, file)}\n")
                        continue
                    _count_submitted_file += 1
                    result = self.scan_file(os.path.join(root, file), _f_file_name)
                    if result:
                        _count_infected_file += 1
                        _contents = f'datetime="{datetime.today().strftime("%Y-%m-%d %H:%M:%S")}",scan_id="{_log_scan_id}",os="{_log_os_ver}",' \
                                    f'hostname="{_log_hostname}",ip="{_log_ipaddr}",infected_file="{result.split("|")[0]}",sha256="{result.split("|")[1]}",' \
                                    f'created_at="{result.split("|")[2]}",modified_at="{result.split("|")[3]}"\n'
                        self.scan_result_logs(_contents)
            QMessageBox.information(self, "Scan Completed", "Scanning Completed. Please check the log for the result.")
            if _count_infected_file >= 1:
                self.log_message(f'<span style="background-color:#888;"> Scan Completed.! </span> <br>- O.M.G... <span style="background-color:red;"> [{_count_infected_file}] </span> file infected.<br>- See "{_scan_result_logs_}"<br>')
            else:
                _contents = f'datetime="{datetime.today().strftime("%Y-%m-%d %H:%M:%S")}",scan_id="{_log_scan_id}",os="{_log_os_ver}",' \
                            f'hostname="{_log_hostname}",ip="{_log_ipaddr}",infected_file="None"\n'
                self.scan_result_logs(_contents)
                self.log_message(f'<span style="background-color:#888;"> Scan Completed.! </span> <br>- no malware Found.! happy happy:)<br>')

        except Exception as e:
            self.log_message(f"Error: {e}\n")

    def scan_file(self, file, _f_file_name):
        try:
            self.log_message(f"Scanning: {file}\n")
            with open(file, 'rb') as f:
                data = f.read()
                sha256_hash = hashlib.sha256(data).hexdigest()
                with open(_engine_extract_file_, 'r') as engine_db:
                    for line in engine_db:
                        if sha256_hash in line:
                            self.log_message(f"{_f_file_name} is Malware\n", color='red')
                            # with open(_scan_result_logs_, 'a') as f:
                            #     f.write(f"{_ctime_} {_f_file_name} {sha256_hash}\n")
                            _scan_result = f'{_f_file_name}|{sha256_hash}|{self.get_create_date(file)}|{self.get_modify_date(file)}'
                            return _scan_result
                            # break
        except Exception as e:
            self.log_message(f"Error: {e}\n")
    
    def scan_result_logs(self, _contents):
        _make_output_dir = f'{_home_path_}/output'
        _mode = 'w'

        if os.path.exists(_make_output_dir):
            if os.path.exists(_scan_result_logs_):
                _mode = 'a'
        else:
            _mode = 'w'
            os.makedirs(_make_output_dir)

        with open(_scan_result_logs_, _mode) as fa:
            fa.write('%s' % _contents)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MalwareScanner()
    window.show()
    sys.exit(app.exec())
