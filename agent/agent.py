import os
import psutil
import time
import requests
import subprocess
import ipaddress
import ctypes
import json
import tkinter as tk
from tkinter import messagebox
from plyer import notification
from dotenv import load_dotenv

load_dotenv()
SERVER_API_URL = os.getenv('SERVER_API_URL', 'http://127.0.0.1:5000/api/evaluate')
AGENT_SECRET = os.getenv('AGENT_SECRET_KEY', 'default_secret_123')
CHECK_INTERVAL_SECONDS = 10
CACHE_FILE = 'signature_cache.json'

WHITELISTED_CIDRS = [
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "8.8.8.8/32", "8.8.4.4/32"
]

# OPTIMIZATION: Persistent local caching
def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f: return json.load(f)
        except: return {}
    return {}

def save_cache():
    try:
        with open(CACHE_FILE, 'w') as f: json.dump(signature_cache, f)
    except: pass

signature_cache = load_cache()
prompted_ips = set()

root = tk.Tk()
root.withdraw()

def is_admin():
    try: return os.getuid() == 0
    except AttributeError: return ctypes.windll.shell32.IsUserAnAdmin() != 0

def is_whitelisted(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in ipaddress.ip_network(cidr) for cidr in WHITELISTED_CIDRS)
    except: return True

def verify_signature(exe_path):
    if not exe_path: return False
    if exe_path in signature_cache: return signature_cache[exe_path]
    try:
        cmd = f"(Get-AuthenticodeSignature '{exe_path}').Status -eq 'Valid'"
        result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True, creationflags=0x08000000)
        is_signed = "True" in result.stdout
        signature_cache[exe_path] = is_signed
        save_cache() # Save to hard drive immediately
        return is_signed
    except: return False

def calculate_local_threat_score(process_name, exe_path, remote_port, is_signed):
    score = 0
    reasons = []

    exe_path_lower = str(exe_path).lower()
    suspicious_paths = ['\\appdata\\', '\\temp\\', '\\downloads\\', '\\programdata\\']
    if any(susp_folder in exe_path_lower for susp_folder in suspicious_paths):
        score += 30
        reasons.append("Running from temp/user directory")

    if not is_signed:
        score += 20
        reasons.append("Unsigned binary")

    suspicious_ports = [4444, 6667, 1337, 4445, 9999]
    standard_ports = [80, 443]
    if remote_port in suspicious_ports:
        score += 40
        reasons.append(f"Malicious port ({remote_port})")
    elif remote_port not in standard_ports:
        score += 10
        reasons.append(f"Non-standard port ({remote_port})")

    lotl_bins = ['powershell.exe', 'cmd.exe', 'certutil.exe', 'mshta.exe', 'bitsadmin.exe']
    if process_name.lower() in lotl_bins and not is_signed:
        score += 50
        reasons.append("Impersonating system binary")
    elif process_name.lower() in lotl_bins and remote_port not in standard_ports:
        score += 35
        reasons.append("System binary making unusual connection")

    return min(score, 100), reasons

def block_ip_firewall(ip):
    rule_name = f"EDR_BLOCK_{ip.replace('.', '_')}"
    cmd = f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Outbound -Action Block -RemoteAddress {ip}'
    try:
        res = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True, creationflags=0x08000000)
        if res.returncode == 0:
            messagebox.showinfo("Success", f"Blocked {ip} in Windows Firewall.")
        else:
            messagebox.showerror("Error", f"Failed to block. Ensure Agent is Admin.\n{res.stderr}")
    except Exception as e: print(e)

def handle_threat(ip, process_name, categories, local_reasons):
    if ip in prompted_ips: return
    prompted_ips.add(ip)
    reason_str = ", ".join(local_reasons) if local_reasons else "Unknown behavior"
    try:
        notification.notify(title="🚨 EDR Threat Detected!", message=f"App: {process_name}\nIP: {ip}\nHeuristics: {reason_str}", app_name="DevSecOps EDR", timeout=7)
    except: pass

    msg = (f"DANGEROUS CONNECTION DETECTED\n\nApp: {process_name}\nIP: {ip}\nCloud Threats: {categories}\nLocal Heuristics: {reason_str}\n\nBlock this IP in Windows Firewall?")
    if messagebox.askyesno("Intrusion Prevention System (IPS)", msg, icon='warning'):
        block_ip_firewall(ip)

print(f"Windows Edge-AI Agent Running. Telemetry target: {SERVER_API_URL}...")
if not is_admin(): print("WARNING: Not running as Administrator. IPS blocking will fail.")

while True:
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr and conn.status == 'ESTABLISHED' and conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    if is_whitelisted(remote_ip): continue
                        
                    exe_path = proc.exe()
                    process_name = proc.name()
                    is_signed = verify_signature(exe_path)
                    
                    local_score, heuristic_reasons = calculate_local_threat_score(process_name, exe_path, remote_port, is_signed)
                    
                    if local_score >= 30 or not is_signed:
                        payload = {
                            "ip": remote_ip, "process": process_name,
                            "local_risk_score": local_score, "heuristics": ", ".join(heuristic_reasons)
                        }
                        
                        # OPTIMIZATION: Send Auth Headers
                        headers = {'Authorization': f'Bearer {AGENT_SECRET}'}
                        res = requests.post(SERVER_API_URL, json=payload, headers=headers, timeout=3)
                        
                        if res.status_code == 200:
                            data = res.json()
                            if data.get('status') == 'DANGEROUS' or local_score >= 70:
                                handle_threat(remote_ip, process_name, data.get('categories', 'Unknown'), heuristic_reasons)
                except (psutil.NoSuchProcess, psutil.AccessDenied): pass
        time.sleep(CHECK_INTERVAL_SECONDS)
        root.update()
    except Exception as e: time.sleep(5)