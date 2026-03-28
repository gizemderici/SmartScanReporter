import os
import subprocess


BASE_DIR = os.path.dirname(__file__)
XML_DOSYASI = os.path.join(BASE_DIR, "scan_results", "output.xml")


def run_nmap_scan(target: str):
    os.makedirs(os.path.dirname(XML_DOSYASI), exist_ok=True)
    command = ["nmap", "-sV", "-O", "-oX", XML_DOSYASI, target]
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode == 0, result.stderr
