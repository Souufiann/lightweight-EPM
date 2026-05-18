import os
import sqlite3
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'MISSING_KEY')
THREAT_THRESHOLD = int(os.getenv('THREAT_THRESHOLD', 20))
CACHE_EXPIRY_DAYS = int(os.getenv('CACHE_EXPIRY_DAYS', 1))
DB_PATH = '/app/data/threat_cache.db'

ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VOIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH Abuse", 23: "IoT Targeted"
}

def init_db():
    os.makedirs('/app/data', exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS ip_cache
                 (ip TEXT PRIMARY KEY, score INTEGER, categories TEXT, last_checked TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS event_log
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME, 
                  ip TEXT, process TEXT, score INTEGER, status TEXT, categories TEXT)''')
    conn.commit()
    conn.close()

def check_abuseipdb(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': API_KEY}
    params = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': 'true'}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()['data']
            score = data['abuseConfidenceScore']
            categories = set()
            if 'reports' in data:
                for report in data['reports']:
                    for cat in report.get('categories', []):
                        categories.add(cat)
            cat_strings = [ABUSE_CATEGORIES.get(c, "Unknown") for c in categories]
            final_cats = ", ".join(cat_strings) if cat_strings else "None"
            return score, final_cats
    except Exception as e: 
        print(f"API Error: {e}")
    return 0, "None"

@app.route('/api/evaluate', methods=['POST'])
def evaluate_ip():
    data = request.json
    ip = data.get('ip')
    process_name = data.get('process')
    if not ip: return jsonify({"error": "Missing IP"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now()

    c.execute("SELECT score, categories, last_checked FROM ip_cache WHERE ip=?", (ip,))
    row = c.fetchone()

    score, categories = 0, "None"
    if row and (now - datetime.strptime(row[2], "%Y-%m-%d %H:%M:%S.%f") < timedelta(days=CACHE_EXPIRY_DAYS)):
        score, categories = row[0], row[1]
    else:
        score, categories = check_abuseipdb(ip)
        c.execute("REPLACE INTO ip_cache (ip, score, categories, last_checked) VALUES (?, ?, ?, ?)", (ip, score, categories, now))

    status = "DANGEROUS" if score >= THREAT_THRESHOLD else "SUSPICIOUS" if score > 0 else "SAFE"
    
    c.execute("INSERT INTO event_log (timestamp, ip, process, score, status, categories) VALUES (?, ?, ?, ?, ?, ?)", 
              (now.strftime("%Y-%m-%d %H:%M:%S"), ip, process_name, score, status, categories))
    conn.commit()
    conn.close()
    
    print(f"[{status}] App '{process_name}' -> {ip} (Score: {score})")
    return jsonify({"ip": ip, "score": score, "status": status, "categories": categories})

@app.route('/api/graph-data')
def graph_data():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = f"""
        SELECT strftime('%H:%M', timestamp) as time_min,
               SUM(CASE WHEN score < {THREAT_THRESHOLD} THEN 1 ELSE 0 END) as safe_count,
               SUM(CASE WHEN score >= {THREAT_THRESHOLD} THEN 1 ELSE 0 END) as threat_count
        FROM event_log WHERE timestamp >= datetime('now', '-30 minutes')
        GROUP BY time_min ORDER BY time_min ASC
    """
    c.execute(query)
    rows = c.fetchall()
    conn.close()
    return jsonify({
        "labels": [row[0] for row in rows],
        "safe": [row[1] for row in rows],
        "threats": [row[2] for row in rows]
    })

@app.route('/api/recent-events')
def recent_events():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Fetch the 20 most recent logs
    c.execute("SELECT timestamp, process, ip, score, status, categories FROM event_log ORDER BY id DESC LIMIT 20")
    rows = c.fetchall()
    conn.close()
    
    events = []
    for r in rows:
        events.append({
            "timestamp": r[0], "process": r[1], "ip": r[2], 
            "score": r[3], "status": r[4], "categories": r[5]
        })
    return jsonify(events)

HTML_DASHBOARD = """
<!DOCTYPE html>
<html>
<head>
    <title>DevSecOps EDR Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f6; padding: 20px; color: #333; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 20px;}
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .status-SAFE { color: #2ecc71; font-weight: bold; }
        .status-SUSPICIOUS { color: #f39c12; font-weight: bold; }
        .status-DANGEROUS { color: #e74c3c; font-weight: bold; }
    </style>
</head>
<body>
    <h2>🛡️ Endpoint Network Telemetry</h2>
    
    <div class="card">
        <h3>Live Connections (Last 30 Minutes)</h3>
        <canvas id="telemetryChart" style="max-height: 300px;"></canvas>
    </div>

    <div class="card">
        <h3>Recent Threat Intelligence Logs</h3>
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Process</th>
                    <th>Remote IP</th>
                    <th>Threat Score</th>
                    <th>Status</th>
                    <th>Categories</th>
                </tr>
            </thead>
            <tbody id="logTableBody">
                </tbody>
        </table>
    </div>

    <script>
        // --- Graph Logic ---
        const ctx = document.getElementById('telemetryChart').getContext('2d');
        const telemetryChart = new Chart(ctx, {
            type: 'line',
            data: { labels: [], datasets: [
                { label: 'Safe Connections', borderColor: '#2ecc71', backgroundColor: 'rgba(46, 204, 113, 0.2)', data: [], fill: true, tension: 0.3 },
                { label: 'Threats Detected', borderColor: '#e74c3c', backgroundColor: 'rgba(231, 76, 60, 0.2)', data: [], fill: true, tension: 0.3 }
            ]},
            options: { responsive: true, animation: false, scales: { y: { beginAtZero: true, suggestedMax: 10 } } }
        });

        async function updateDashboard() {
            try {
                // Update Graph
                const graphRes = await fetch('/api/graph-data');
                const graphData = await graphRes.json();
                telemetryChart.data.labels = graphData.labels;
                telemetryChart.data.datasets[0].data = graphData.safe;
                telemetryChart.data.datasets[1].data = graphData.threats;
                telemetryChart.update();

                // Update Table
                const tableRes = await fetch('/api/recent-events');
                const tableData = await tableRes.json();
                const tbody = document.getElementById('logTableBody');
                tbody.innerHTML = ''; // Clear old rows
                
                tableData.forEach(event => {
                    const row = `<tr>
                        <td>${event.timestamp}</td>
                        <td><strong>${event.process}</strong></td>
                        <td>${event.ip}</td>
                        <td>${event.score}/100</td>
                        <td class="status-${event.status}">${event.status}</td>
                        <td><small>${event.categories}</small></td>
                    </tr>`;
                    tbody.innerHTML += row;
                });
            } catch (err) { console.error("Error fetching dashboard data:", err); }
        }
        
        updateDashboard(); 
        setInterval(updateDashboard, 5000); // Refresh both every 5 seconds
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard(): 
    return render_template_string(HTML_DASHBOARD)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)