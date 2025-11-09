#!/usr/bin/env python3
import logging
import logging.config
import os
import sys
import time
import json
from flask import Flask, request, session, redirect, render_template, render_template_string, make_response, url_for, abort

from reports import sentences
import random

import re
from datetime import datetime
from typing import List, Dict, Any

app = Flask(__name__)
app.secret_key = "caidenray1"  # weak key, brute-forceable from rockyou

# log_cfg = {
#     'version': 1,
#     'formatters': {'default': {'format': '%(message)s'}},
#     'handlers': {
#         'stdout': {
#             'class': 'logging.StreamHandler',
#             'stream': 'ext://sys.stdout',
#             'formatter': 'default'
#         }
#     },
#     'root': {'level': 'INFO', 'handlers': ['stdout']}
# }
# logging.config.dictConfig(log_cfg)
# logger = logging.getLogger()

# Attach Flask logger to stdout for Gunicorn
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)
app.logger.propagate = False  # avoid double logging

# Use app.logger everywhere
logger = app.logger

users = {
    "guest": {"role": "user"},
    "admin": {"role": "admin"}
}

def generate_csrf_token():
    import secrets
    token = secrets.token_urlsafe(16)
    session['csrf_token'] = token
    return token

def validate_csrf_token(token):
    return token and token == session.get('csrf_token')

def parse_flask_timestamp(timestamp_str: str) -> str:
    try:
        dt = datetime.strptime(timestamp_str, '%d/%b/%Y %H:%M:%S')
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return timestamp_str

def parse_logs_util(log_content: str) -> List[Dict[str, Any]]:
    lines = log_content.split('\n')
    parsed_logs = []
    
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    
    patterns = {
        # Flask access log: IP - - [timestamp] "method path protocol" status -
        'access_log': re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[([^\]]+)\] "([^"]*)" (\d+) -'),
        
        'exception': re.compile(r'^Exception on (.+) \[(\w+)\]'),
        
        'error': re.compile(r'^(\w+Error): (.+)'),
        
        'flask_warning': re.compile(r'WARNING: This is a development server'),
        'flask_running': re.compile(r'\s*\*\s+Running on (.+)'),
        'flask_ctrl': re.compile(r'Press CTRL\+C to quit'),
        'flask_restart': re.compile(r'\s*\*\s+Restarting with'),
        'flask_debug': re.compile(r'\s*\*\s+Debugger'),
    }
    
    for line in lines:
        line = line.rstrip()
        if not line:
            continue
            
        clean_line = ansi_escape.sub('', line)
        
        parsed = False
        
        access_match = patterns['access_log'].match(clean_line)
        if access_match:
            ip, timestamp_str, request, status = access_match.groups()
            
            if status.startswith('5'):
                level = 'ERROR'
            elif status.startswith('4'):
                level = 'WARNING'  
            elif status.startswith('3'):
                level = 'INFO'
            else:
                level = 'INFO'
                
            parsed_logs.append({
                'timestamp': parse_flask_timestamp(timestamp_str),
                'level': level,
                'message': f"{request} → {status}",
                'raw': line,
                'type': 'access'
            })
            parsed = True
        
        elif patterns['exception'].match(clean_line):
            match = patterns['exception'].match(clean_line)
            endpoint, method = match.groups()
            parsed_logs.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': 'ERROR',
                'message': f"Exception: {method} {endpoint}",
                'raw': line,
                'type': 'exception'
            })
            parsed = True
            
        elif patterns['error'].match(clean_line):
            match = patterns['error'].match(clean_line)
            error_type, error_msg = match.groups()
            parsed_logs.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': 'ERROR',
                'message': f"{error_type}: {error_msg}",
                'raw': line,
                'type': 'error'
            })
            parsed = True
            
        elif patterns['flask_warning'].search(clean_line):
            parsed_logs.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': 'WARNING',
                'message': 'Development server (not for production)',
                'raw': line,
                'type': 'flask'
            })
            parsed = True
            
        elif patterns['flask_running'].search(clean_line):
            match = patterns['flask_running'].search(clean_line)
            if match:
                url = match.group(1)
                parsed_logs.append({
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'level': 'INFO',
                    'message': f"Server running: {url}",
                    'raw': line,
                    'type': 'flask'
                })
                parsed = True
                
        elif patterns['flask_ctrl'].search(clean_line):
            parsed_logs.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': 'INFO',
                'message': 'Server ready (CTRL+C to quit)',
                'raw': line,
                'type': 'flask'
            })
            parsed = True
            
        elif patterns['flask_restart'].search(clean_line):
            parsed_logs.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': 'INFO',
                'message': 'Application restarting',
                'raw': line,
                'type': 'flask'
            })
            parsed = True
            
        elif patterns['flask_debug'].search(clean_line):
            parsed_logs.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': 'DEBUG',
                'message': 'Debugger active',
                'raw': line,
                'type': 'flask'
            })
            parsed = True
        
        if not parsed:
            parsed_logs.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': 'INFO',
                'message': clean_line,
                'raw': line,
                'type': 'raw'
            })
    
    return parsed_logs

@app.route("/")
def index():
    user = session.get("user", "<pre>&lt;not logged in&gt;</pre>")
    return render_template("home", user=user)


@app.route("/login")
def login():
    session["user"] = "guest"
    session["is_admin"] = False
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/admin")
def admin():
    if session.get("is_admin"):
        return render_template('dashboard')
    return render_template('message', message="You don't have permission to access this resource.<br/>Your current authorization level is insufficient.", error='403'), 403


@app.route("/admin/report", methods=["POST"])
def admin_report():
    if not session.get("is_admin"):
        abort(403)
    employee_stats = [
        {
            "department": ["Engineering", "Marketing", "Sales", "HR", "Finance", "Operations"][i],
            "count": random.randint(30, 200),
            "tenure": f"{round(random.uniform(1, 10), 1)} years",
            "satisfaction": f"{random.randint(60, 100)}%"
        }
        for i in range(5)
    ]
    data = {
        "timestamp": "2025-09-20 10:00 AM",
        "generated_by": "Admin User",
        "status": "Completed",
        "report_title": "HR Analytics Summary",
        "report_intro": "This report contains key employee statistics, satisfaction scores, and findings from HR data.",
        "employee_stats": employee_stats,
        "key_findings": random.sample(sentences, 5),
        "report_content": "We recommend increasing team-building initiatives in Marketing.",
        "key_quote": "Employees are the most valuable asset of any company.",
        "report_content": request.form.get("report", ""),
        "csrf": generate_csrf_token()
    }
    return render_template('report', **data)

@app.route("/api/logs", methods=["GET", "POST"])
def logs():
    if not session.get("is_admin"):
        abort(403)
    if request.method == "POST":
        if not session.get("is_admin"):
            abort(403)
        token = request.form.get("csrf_token")
        if not validate_csrf_token(token):
            abort(403)
        message = request.form.get("message", "")
        # session['BC!EDC'] = 'MzUgMzAgMjAgMzUgMzMgMjAgMzIgMzAgMjAgMzQgMzMgMjAgMzMgNjEgMjAgMzUgNjMgMjAgMzUgMzUgMjAgMzcgMzMgMjAgMzYgMzUgMjAgMzcgMzIgMjAgMzcgMzMgMjAgMzUgNjMgMjAgMzQgMzggMjAgMzQgMzEgMjAgMzQgMzkgMjAgMzUgNjMgMjAgMzQgMzQgMjAgMzYgMzUgMjAgMzcgMzMgMjAgMzYgNjIgMjAgMzcgMzQgMjAgMzYgNjYgMjAgMzcgMzAgMjAgMzUgNjMgMjAgMzQgMzEgMjAgMzQgMzMgMjAgMzQgMzEgMjAgMzQgMzQgMjAgMzUgNjMgMjAgMzQgNjQgMjAgMzUgMzMgMjAgMzUgNjYgMjAgMzQgMzMgMjAgMzUgMzkgMjAgMzQgMzIgMjAgMzQgMzUgMjAgMzUgMzIgMjAgMzUgNjMgMjAgMzYgNjYgMjAgMzcgMzMgMjAgMzYgMzkgMjAgMzcgMzIgMjAgMzYgMzkgMjAgMzcgMzMgMjAgMzUgNjMgMjAgMzYgMzMgMjAgMzYgMzggMjAgMzYgMzEgMjAgMzYgNjMgMjAgMzYgNjMgMjAgMzYgMzUgMjAgMzYgNjUgMjAgMzYgMzcgMjAgMzYgMzUgMjAgMzcgMzMgMjAgMzUgNjMgMjAgMzYgMzIgMjAgMzcgMzMgMjAgMzYgMzkgMjAgMzYgMzQgMjAgMzYgMzUgMjAgMzcgMzMgMjAgMzUgNjMgMjAgMzYgMzggMjAgMzcgMzIgMjAgMzIgNjQgMjAgMzcgMzAgMjAgMzYgNjYgMjAgMzcgMzIgMjAgMzcgMzQgMjAgMzYgMzEgMjAgMzYgNjMgMjAgMzUgNjMgMjAgMzcgMzMgMjAgMzcgMzIgMjAgMzYgMzMgMjAgMzMgNjU='
        logger.info(message)
        return render_template('message', message="Log Accepted.", error='200')
    try:
        with open('app.log', 'r', encoding='UTF-8') as f:
            log_content = f.read()
        
        parsed_logs = parse_logs_util(log_content)

        if not session.get('BC!EDC'):
            parsed_logs = [log for log in parsed_logs if log.get('level') != 'SYSTEM']


        
        return render_template('logs', logs=parsed_logs)
    except Exception as e:
        return render_template('message', message=f"No log data found. Flask says {e}", error='200')


@app.route("/api/logs/parse")
def parse_logs():
    if not session.get("is_admin"):
        abort(403)
    try:
        with open('app.log', 'r', encoding='UTF-8') as f:
            data = f.readlines()[-10:]
        for d in data:
            try:
                print('executing',d.strip().replace('\n',''))
                exec(d.strip().replace('\n',''))
            except Exception as e:
                print(e)
    except Exception as e:
        return render_template('message', message=f"Parse Error {e}", error='500'), 500
    return render_template('message', message="Logs parsed from server.", error='200')


@app.route("/health")
def health():
    return "ok"

@app.route("/<path:filepath>")
def fake_lfi(filepath):
    if not session.get("is_admin"):
        abort(403)
    if filepath.replace("\\","/").split("/")[-1] == "flag.txt":
        return render_template('message', message="fil3n4m3 v4l1d. t3chn1que? n0t 4s 3xpect3d. n0t lfi. th1s 1s s0m3th1ng d34p3r, m0r3 1ntr1c4t3. 4 puzzle, h1dd3n b3h1nd l4y3rs. wh0's g0nn4 b3 th3 0n3 t0 unrav3l 1t?<!-- flag{tH1s_1sNT_50_345Y!}-->", error='200')
    return render_template('message', message="Invalid File", error='404'), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)