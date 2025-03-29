from flask import Flask, render_template, request, redirect, url_for
import pandas as pd
import re
import os
from collections import defaultdict

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'

# Create directories if missing
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('sample_logs', exist_ok=True)

def parse_log(file_path):
    """Parse log file into structured DataFrame with error handling"""
    log_entries = []
    log_pattern = r'^(\S+) (\S+) (\S+) \[([^]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = re.match(log_pattern, line)
                if match:
                    log_entries.append({
                        'ip': match.group(1),
                        'timestamp': match.group(4),
                        'method': match.group(5),
                        'path': match.group(6),
                        'protocol': match.group(7),
                        'status': match.group(8),
                        'size': match.group(9)
                    })
        return pd.DataFrame(log_entries)
    except Exception as e:
        print(f"Error parsing log: {e}")
        return pd.DataFrame()

def detect_anomalies(df):
    """Enhanced anomaly detection with aggregation"""
    anomalies = []
    
    # Rule 1: High frequency requests (1000+ requests)
    ip_counts = df['ip'].value_counts()
    for ip, count in ip_counts[ip_counts > 1000].items():
        anomalies.append({
            'type': 'High Frequency',
            'ip': ip,
            'count': count,
            'message': f'Excessive requests ({count}) from single IP'
        })
    
    # Rule 2: High error rate (50+ 4xx/5xx errors)
    error_df = df[df['status'].str.startswith(('4', '5'))]
    error_counts = error_df.groupby('ip')['status'].count()
    for ip, count in error_counts[error_counts > 50].items():
        anomalies.append({
            'type': 'High Error Rate',
            'ip': ip,
            'count': count,
            'message': f'High error rate ({count} errors) from IP'
        })
    
    # Rule 3: Suspicious paths (grouped)
    suspicious_paths = r'(^/wp-admin|^/admin|\.env$|/config/|/\.git|/\.svn)'
    suspicious = df[df['path'].str.contains(suspicious_paths, case=False, na=False)]
    grouped = suspicious.groupby(['ip', 'path']).size().reset_index(name='counts')
    for _, row in grouped.iterrows():
        anomalies.append({
            'type': 'Suspicious Path',
            'ip': row['ip'],
            'count': row['counts'],
            'message': f'Accessed {row["path"]} ({row["counts"]} times)'
        })
    
    # Rule 4: Failed logins (401 on login pages)
    failed_logins = df[
        (df['path'].str.contains('/login', case=False)) &
        (df['status'] == '401')
    ]
    login_counts = failed_logins.groupby('ip').size()
    for ip, count in login_counts[login_counts > 5].items():
        anomalies.append({
            'type': 'Failed Logins',
            'ip': ip,
            'count': count,
            'message': f'{count} failed login attempts'
        })
    
    return anomalies

@app.route('/', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'logfile' not in request.files:
            return redirect(request.url)
            
        file = request.files['logfile']
        if file.filename == '':
            return redirect(request.url)
            
        if file and file.filename.endswith('.log'):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp.log')
            file.save(file_path)
            return redirect(url_for('results'))
    
    return render_template('upload.html')

@app.route('/results')
def results():
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp.log')
        df = parse_log(file_path)
        if df.empty:
            return redirect(url_for('upload'))
        
        anomalies = detect_anomalies(df)
        return render_template('results.html', anomalies=anomalies)
    except Exception as e:
        print(f"Error processing results: {e}")
        return redirect(url_for('upload'))

if __name__ == '__main__':
    app.run(debug=True)