# import yara
# import os

from antivirus.define_structures import create_database

# rule_files = []
# for file in os.listdir("D:\\Porcupine Project\\Porcupine\\antivirus\\definitions\\rules-master\\malware\\Operation_Blockbuster"):
#     if file.endswith('.yar') or file.endswith('.yara'):
#         rule_file_path = os.path.join("D:\\Porcupine Project\\Porcupine\\antivirus\\definitions\\rules-master\\malware\\Operation_Blockbuster", file)
#         rule_files.append(rule_file_path)

# def concatenate_and_compile(rule_files, output_file):
#   with open(output_file, "a") as f:
#     for filename in rule_files:
#       with open(filename, "r") as rule_file:
#         f.write(rule_file.read())
#   yara.compile(output_file)
  
# output_file = "D:\\Porcupine Project\\Porcupine\\models\\yara_rules\\combined_malware_rules.yar"
# concatenate_and_compile(rule_files, output_file)
# yara.compile(output_file)
# compiled = yara.compile("D:\\Porcupine Project\\Porcupine\\models\\yara_rules\\combined_rules.yar")
# compiled.save("D:\\Porcupine Project\\Porcupine\\models\\yara_rules\\compiled_combined_rules.yar")

# for filename in rule_files:
#     with open(filename, "r+") as f:
#       data = f.read()
#       data = data.replace("./", "D:/Porcupine Project/Porcupine/antivirus/definitions/rules-master/")
#       f.seek(0)
#       f.write(data)
#       f.truncate()


create_database()

# from antivirus.filechecker import extract_info

# data = extract_info("C:/Users/Adell/Downloads/fpc-3-2-0-i386-win32.exe")

# print(data)
# import pefile

# pe = pefile.PE("C:/Users/Adell/Downloads/python-3.7.4.exe")
# for section in pe.sections:
#     # print(section.get_data())
#     if b"IsDebuggerPresent" in section.get_data():
#         print("debuger?")