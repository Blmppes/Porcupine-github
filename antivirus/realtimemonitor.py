import time
from PySide6.QtCore import Signal, QThread, QObject
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import win32file

class Monitorer(QObject):
    file_event_signal = Signal(str, str)

class AntivirusHandler(FileSystemEventHandler):
    def __init__(self, signal_manager):
        super().__init__()
        self.signal_manager = signal_manager

    def on_created(self, event):
        if not event.is_directory:
            if event.src_path.startswith(".\models"):
                return
            self.signal_manager.file_event_signal.emit(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            if event.src_path.startswith(".\models"):
                return
            self.signal_manager.file_event_signal.emit(event.src_path, "modified")

    def on_deleted(self, event):
        if not event.is_directory:
            if event.src_path.startswith(".\models"):
                return
            self.signal_manager.file_event_signal.emit(event.src_path, "deleted")

class FileMonitorThread(QThread):
    def __init__(self, path, signal_manager, scanner):
        super().__init__()
        self.path = path
        self.signal_manager = signal_manager
        self.observer = Observer()
        self.scanner = scanner

    def get_drives(self):
        drives = []
        bitmask = win32file.GetLogicalDrives()
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            if bitmask & 1:
                drives.append(letter)
            bitmask >>= 1
        return drives

    def run(self):
        drives_before = set(self.get_drives())
        event_handler = AntivirusHandler(self.signal_manager)
        self.observer.schedule(event_handler, self.path, recursive=True)
        self.observer.start()
        try:
            while not self.isInterruptionRequested():
                time.sleep(1)
                drives_after = set(self.get_drives())
                new_drives = drives_after - drives_before
                if new_drives:
                    for drive in new_drives:
                        print(f"New USB device detected: {drive}:\\")
                        usbdir = self.scanner.scan_directory(f"{drive}:\\", False)
                        if(usbdir):
                            for ifile in usbdir:
                                print(f"Infected file: {ifile}")
                        else:
                            print("No infected file found in new USB")

                drives_before = set(self.get_drives())
        except Exception as e:
            print(f"Exception: {e}")
        finally:
            self.observer.stop()
            self.observer.join()

    def process_event(self, file_path, event_type):
        print(f"File {event_type}: {file_path}")
        if(event_type in ["created", "modified"]):
            if(self.scanner.scan_file(file_path)):
                print("File infected!!!")
            else:
                print("File is save :)")