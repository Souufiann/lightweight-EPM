import os
import psutil
import time
import requests
import subprocess
import ipaddress
import ctypes
import tkinter as tk
from tkinter import messagebox
from plyer import notification
from dotenv import load_dotenv

load_dotenv()
SERVER_API_URL = os.getenv('SERVER_API_URL', 'http://127.0.0.1:5000/api/evaluate')
CHECK_INTERVAL_SECONDS = 10

WHITELISTED_CIDRS = [
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "8.8.8.8/32", "8.8.4.4/32"
]

signature_cache = {}
prompted_ips = set()

# Hidden Tkinter root for messageboxes
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
        return is_signed
    except: return False

def calculate_local_threat_score(process_name, exe_path, remote_port, is_signed):
    """
    Evaluates local process context to generate a heuristic threat score (0-100).
    Acts as a lightweight edge-AI to catch anomalies before querying the server.
    """
    score = 0
    reasons = []

    # 1. Location Heuristics
    exe_path_lower = str(exe_path).lower()
    suspicious_paths = ['\\appdata\\', '\\temp\\', '\\downloads\\', '\\programdata\\']
    
    if any(susp_folder in exe_path_lower for susp_folder in suspicious_paths):
        score += 30
        reasons.append("Running from temp/user directory")

    # 2. Signature Heuristics
    if not is_signed:
        score += 20
        reasons.append("Unsigned binary")

    # 3. Port/Protocol Heuristics
    suspicious_ports = [4444, 6667, 1337, 4445, 9999]
    standard_ports = [80, 443]
    
    if remote_port in suspicious_ports:
        score += 40
        reasons.append(f"Malicious port ({remote_port})")
    elif remote_port not in standard_ports:
        score += 10
        reasons.append(f"Non-standard port ({remote_port})")

    # 4. Living off the Land (LotL) Heuristics
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
            messagebox.showerror("Error", f"Failed to block. Ensure Agent is running as Admin.\n{res.stderr}")
    except Exception as e: print(e)

def handle_threat(ip, process_name, categories, local_reasons):
    if ip in prompted_ips: return
    prompted_ips.add(ip)
    
    reason_str = ", ".join(local_reasons) if local_reasons else "Unknown behavior"
    
    try:
        notification.notify(
            title="🚨 EDR Threat Detected!",
            message=f"App: {process_name}\nIP: {ip}\nHeuristics: {reason_str}",
            app_name="DevSecOps EDR", timeout=7
        )
    except: pass

    msg = (f"DANGEROUS CONNECTION DETECTED\n\n"
           f"App: {process_name}\n"
           f"IP: {ip}\n"
           f"Cloud Threats: {categories}\n"
           f"Local Heuristics: {reason_str}\n\n"
           f"Block this IP in Windows Firewall?")
           
    if messagebox.askyesno("Intrusion Prevention System (IPS)", msg, icon='warning'):
        block_ip_firewall(ip)

print(f"Windows Edge-AI Agent Running. Telemetry target: {SERVER_API_URL}...")
if not is_admin():
    print("WARNING: Not running as Administrator. IPS blocking will fail.")

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
                    
                    # 1. Ask our lightweight local heuristic engine
                    local_score, heuristic_reasons = calculate_local_threat_score(
                        process_name, exe_path, remote_port, is_signed
                    )
                    
                    # 2. Query Server only if context is suspicious or unsigned
                    if local_score >= 30 or not is_signed:
                        payload = {
                            "ip": remote_ip, 
                            "process": process_name,
                            "local_risk_score": local_score,
                            "heuristics": ", ".join(heuristic_reasons)
                        }
                        
                        res = requests.post(SERVER_API_URL, json=payload, timeout=3)
                        
                        if res.status_code == 200:
                            data = res.json()
                            cloud_status = data.get('status')
                            cloud_categories = data.get('categories', 'Unknown')
                            
                            # Trigger if Cloud says dangerous OR Local heuristic score is extremely high
                            if cloud_status == 'DANGEROUS' or local_score >= 70:
                                handle_threat(remote_ip, process_name, cloud_categories, heuristic_reasons)
                                
                except (psutil.NoSuchProcess, psutil.AccessDenied): pass
                
        time.sleep(CHECK_INTERVAL_SECONDS)
        root.update() # Keep tkinter event loop alive
    except Exception as e:
        time.sleep(5)