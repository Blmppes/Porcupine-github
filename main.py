import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QFileDialog
from PySide6.QtCore import QThread
from gui.main_window import Ui_MainWindow
from antivirus.scanner import Scanner
from antivirus.realtimemonitor import FileMonitorThread, Monitorer
from antivirus.networking import NetworkThread

class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setupUi(self)

        # Connect the Scan button to the scan_directory method
        self.scanButton.clicked.connect(self.selectDirectory)
        self.firewallSection.clicked.connect(self.show_firewall_page)
        self.statusSection.clicked.connect(self.show_status_page)
        self.scanSection.clicked.connect(self.show_scan_page)

        #Threading

        #Scanner thread
        self.scanner_thread = QThread()  
        self.scanner = Scanner()  
        self.scanner.moveToThread(self.scanner_thread)  
        
        #Real time monitoring thread
        self.monitorer = Monitorer()
        self.file_monitor_thread = FileMonitorThread(".", self.monitorer, self.scanner)
        self.monitorer.moveToThread(self.file_monitor_thread)
        # self.file_monitor_thread.start()
        self.monitorer.file_event_signal.connect(self.file_monitor_thread.process_event)

        #Network thread
        self.network_thread = NetworkThread()  
        self.network_thread.start()

        # Connect signals
        self.scanner.scanningStarted.connect(self.scanningStarted)
        self.scanner.scanningFinished.connect(self.finishScanning)
        self.scanner.progressUpdate.connect(self.updateProgress)
        self.scanner.resultList.connect(self.handleInfectedFilesFound)

    def show_scan_page(self):
        self.stackedWidget.setCurrentWidget(self.scan_page)
    
    def show_firewall_page(self):
        self.stackedWidget.setCurrentWidget(self.firewall_page)

    def show_status_page(self):
        self.stackedWidget.setCurrentWidget(self.status_page)

    def selectDirectory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")  # Open file dialog to select directory
        if directory:
            self.startScanning(directory)

    def scanningStarted(self):
        self.resultTextArea.append("Scanning started...")

    def startScanning(self, directory):
        if (not self.scanner_thread.isRunning()):
            self.scanner_thread.start()
        self.resultTextArea.clear()
        self.scanButton.setEnabled(False)
        self.scanner.usescanner(directory)

    def finishScanning(self, status):
        if self.scanner_thread.isRunning():
            self.scanner_thread.quit()
            self.scanner_thread.wait()
        self.resultTextArea.append(status)
        self.scanButton.setEnabled(True)

    def handleInfectedFilesFound(self, infected_files):
        self.resultTextArea.append("Infected files:")
        for file in infected_files:
            self.resultTextArea.append(file)

    def updateProgress(self, message):
        self.resultTextArea.append(message)

    def closeEvent(self, event):
        self.file_monitor_thread.requestInterruption()
        self.file_monitor_thread.wait()
        self.network_thread.stop()
        self.network_thread.requestInterruption()
        self.network_thread.wait()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
