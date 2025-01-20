import os
import hashlib
from PySide6.QtCore import QObject, Signal, QCoreApplication
from antivirus.define_structures import add_scanned_file, is_file_scanned, delete_file
import yara
import pefile
import mimetypes
from antivirus.filechecker import extract_info, is_pe_file
import pickle
import joblib

class Scanner(QObject):
    scanningStarted = Signal()
    scanningFinished = Signal(str)
    progressUpdate = Signal(str)
    resultList = Signal(list)
    def __init__(self):
        super().__init__()
        self.load_definitions()

        
    def load_definitions(self):
        # Load virus definitions
        self.md5_set = set()

        with open("antivirus/definitions/full_md5.txt", "r") as file:
            md5_lists = file.read().split()
            for hashes in md5_lists:
                self.md5_set.add(hashes)

        self.sha1_set = set()

        with open("antivirus/definitions/full_sha1.txt", "r") as file:
            sha1_lists = file.read().split()
            for hashes in sha1_lists:
                self.sha1_set.add(hashes)

        self.sha256_set = set()

        with open("antivirus/definitions/full_sha256.txt", "r") as file:
            sha256_lists = file.read().split()
            for hashes in sha256_lists:
                self.sha256_set.add(hashes)

        self.yara_source = "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/"

        self.rules = {
            "anti_debug_vm": yara.compile(filepath=f'{self.yara_source}antidebug_antivm_index.yar'),
            "capabilities": yara.compile(filepath=f'{self.yara_source}capabilities_index.yar'),
            "cve_rules": yara.compile(filepath=f'{self.yara_source}cve_rules_index.yar'),
            "crypto": yara.compile(filepath=f'{self.yara_source}crypto_index.yar'),
            "exploit_kits": yara.compile(filepath=f'{self.yara_source}exploit_kits_index.yar'),
            "malicious_documents": yara.compile(filepath=f'{self.yara_source}maldocs_index.yar'),
            "malware": yara.compile(filepath=f'{self.yara_source}combined_malware_rules.yar'),
            "packers": yara.compile(filepath=f'{self.yara_source}packers_index.yar'),
            "webshells": yara.compile(filepath=f'{self.yara_source}webshells_index.yar'),
            "email": yara.compile(filepath=f'{self.yara_source}email_index.yar'),
            "malware_mobile": yara.compile(filepath=f'{self.yara_source}mobile_malware_index.yar')
        }

        #Load AI models
        self.scan_model = joblib.load("models/model.pkl")
        self.scan_features = pickle.loads(open(os.path.join('models/features.pkl'), 'rb').read())

    def checkFileByAI(self, file):
        data = extract_info(file)
        if data != {}:
            pe_features = list(map(lambda x: data[x], self.scan_features))
            res = self.scan_model.predict([pe_features])[0]
        else:
            print("rong")
            res = 0
        return res

    def usescanner(self, directory):
        self.scanningStarted.emit()
        QCoreApplication.processEvents()
        if directory:
            infected_files = self.scan_directory(directory, True)
            if infected_files:
                self.resultList.emit(infected_files)
            self.scanningFinished.emit(f"{len(infected_files)} infected files found.")
        else:
            self.scanningFinished.emit(f"No files found.")

    def signature_based_scanning(self, file_path, hash_sha256):
        hash_sha1 = hashlib.sha1()
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha1.update(chunk)
                hash_md5.update(chunk)
        hash_sha1 = hash_sha1.hexdigest()
        hash_md5 = hash_md5.hexdigest()
        if(hash_md5 in self.md5_set):
            return True
        if(hash_sha1 in self.sha1_set):
            return True
        if(hash_sha256 in self.sha256_set):
            return True
        return 
    
    def check_crypto_patterns(self, data):
        crypto_patterns = [
            b'AES', b'DES', b'RSA', b'SHA1', b'SHA256', b'MD5'
        ]
        for pattern in crypto_patterns:
            if pattern in data:
                return True
        return False
    
    def sample_file(self, file_path, sample_size=1024):
        file_size = os.path.getsize(file_path)
        samples = []
        with open(file_path, 'rb') as f:
            # Sample the beginning, middle, and end
            positions = [0, max(0, file_size // 2 - sample_size // 2), max(0, file_size - sample_size)]
            for pos in positions:
                f.seek(pos)
                samples.append(f.read(sample_size))
        return samples
    
    def yara_scanning(self, file_path):
        file_info = {
            "file_path": file_path,
            "suggested_categories": []
        }
        
        if is_pe_file(file_path):
            pe = pefile.PE(file_path)
            for section in pe.sections:
                data = section.get_data()
                if(self.rules["anti_debug_vm"].match(data=data)):
                    return True
                if(self.rules["capabilities"].match(data=data)):
                    return True
            pe.close()
        mime_type, _ = mimetypes.guess_type(file_path)
        
        # Check file type based on extension and MIME type
        if mime_type:
            if mime_type.startswith('application/'):
                if 'pdf' in mime_type or 'msword' in mime_type or 'vnd.ms-excel' in mime_type or 'vnd.openxmlformats-officedocument' in mime_type:
                    file_info["type"] = "Document"
                    file_info["suggested_categories"].append("malicious_documents")
                elif 'x-executable' in mime_type:
                    file_info["type"] = "Executable"
                    file_info["suggested_categories"].append("malware")
                    file_info["suggested_categories"].append("packers")
                elif 'x-php' in mime_type or 'x-aspx' in mime_type or 'x-jsp' in mime_type:
                    file_info["type"] = "Web File"
                    file_info["suggested_categories"].append("webshells")
                elif 'x-eml' in mime_type:
                    file_info["type"] = "Email"
                    file_info["suggested_categories"].append("email")

        samples = self.sample_file(file_path)
        for sample in samples:
            if self.check_crypto_patterns(sample):
                file_info["suggested_categories"].append("crypto")
                break
            
        for cate in file_info["suggested_categories"]:
            print(file_path, '\n', cate)
            try:
                if(self.rules[cate].match(file_path)):
                    return True
            except:
                continue
        return False

    def scan_file(self, file_path):
        if not os.path.isfile(file_path):
            return None
        
        #cal hashes
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        hash_sha256 = hash_sha256.hexdigest()
        
        status, scanned = is_file_scanned(hash_sha256)
        if(scanned):
            return status[0]

        if(self.yara_scanning(file_path)):
            print("yara fault")
            add_scanned_file(file_path, hash_sha256, 1)
            return True
        
        if(self.signature_based_scanning(file_path, hash_sha256)):
            print("signature fault")
            add_scanned_file(file_path, hash_sha256, 1)
            return True

        if(is_pe_file(file_path) and self.checkFileByAI(file_path)):
            print("AI fault")
            add_scanned_file(file_path, hash_sha256, 1)
            return True
        
        add_scanned_file(file_path, hash_sha256, 0)
        return False        

    def scan_directory(self, directory_path, upd_ui):
        infected_files = []
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                if(upd_ui):
                    self.progressUpdate.emit(f"Scanning file: {file_path}")
                    QCoreApplication.processEvents()
                if self.scan_file(file_path):
                    infected_files.append(file_path)
        return infected_files
