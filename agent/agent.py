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

def handle_threat(ip, process_name, categories):
    if ip in prompted_ips: return
    prompted_ips.add(ip)
    
    try:
        notification.notify(
            title="🚨 EDR Threat Detected!",
            message=f"App: {process_name}\nIP: {ip}\nThreats: {categories}",
            app_name="DevSecOps EDR", timeout=7
        )
    except: pass

    msg = f"DANGEROUS CONNECTION DETECTED\n\nApp: {process_name}\nIP: {ip}\nThreats: {categories}\n\nBlock this IP in Windows Firewall?"
    if messagebox.askyesno("Intrusion Prevention System (IPS)", msg, icon='warning'):
        block_ip_firewall(ip)

print(f"Windows Agent Running. Sending telemetry to {SERVER_API_URL}...")
if not is_admin():
    print("WARNING: Not running as Administrator. IPS blocking will fail.")

while True:
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr and conn.status == 'ESTABLISHED' and conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    if not is_whitelisted(conn.raddr.ip) and not verify_signature(proc.exe()):
                        # Send to Docker Server
                        payload = {"ip": conn.raddr.ip, "process": proc.name()}
                        res = requests.post(SERVER_API_URL, json=payload, timeout=3)
                        if res.status_code == 200:
                            data = res.json()
                            if data.get('status') == 'DANGEROUS':
                                handle_threat(data['ip'], proc.name(), data.get('categories', 'Unknown'))
                except: pass
        time.sleep(CHECK_INTERVAL_SECONDS)
        root.update() # Keep tkinter event loop alive for messageboxes
    except Exception as e:
        time.sleep(5)