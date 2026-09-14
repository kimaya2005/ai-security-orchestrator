from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import datetime
import random
import time

app = Flask(__name__)
app.secret_key = "secret123"

DB = "database.db"

# ================= DATABASE SETUP =================
def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        login_time TEXT,
        ip TEXT,
        device TEXT,
        status TEXT,
        attempts INTEGER DEFAULT 0
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ================= TEST USER =================
def insert_test_user():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE username='admin'")
    if not cur.fetchone():
        cur.execute("INSERT INTO users(username,password) VALUES(?,?)",
                    ("admin","1234"))

    conn.commit()
    conn.close()

insert_test_user()

# ================= DEVICE & IP CHECK =================
def is_known_device(user_id, device, ip):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("SELECT device, ip FROM login_logs WHERE user_id=?", (user_id,))
    records = cur.fetchall()
    conn.close()

    if len(records) == 0:
        return True

    for d, saved_ip in records:
        if d == device and saved_ip == ip:
            return True

    return False

# ================= LOGIN =================
@app.route('/', methods=['GET','POST'])
def home():
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB)
        cur = conn.cursor()

        cur.execute("SELECT * FROM users WHERE username=? AND password=?",
                    (username,password))
        user = cur.fetchone()

        if user:
            user_id = user[0]

            # check if blocked
            cur.execute("""
            SELECT status FROM login_logs
            WHERE user_id=?
            ORDER BY id DESC LIMIT 1
            """, (user_id,))
            last = cur.fetchone()

            if last and last[0] == "BLOCKED":
                conn.close()
                return "<h2>🚫 Account Blocked. Contact Admin.</h2>"

            ip = request.remote_addr
            device = request.user_agent.string
            login_time = datetime.datetime.now()

            status = "OTP_REQUIRED"

            # 🚨 fraud detection
            if not is_known_device(user_id, device, ip):
                status = "SUSPICIOUS_DEVICE"

            cur.execute("""
            INSERT INTO login_logs(user_id, login_time, ip, device, status)
            VALUES(?,?,?,?,?)
            """, (user_id, login_time, ip, device, status))

            conn.commit()
            conn.close()

            # generate OTP
            otp = random.randint(1000,9999)
            session['otp'] = str(otp)
            session['otp_time'] = time.time()
            session['user_id'] = user_id

            print("🔐 OTP:", otp)

            if status == "SUSPICIOUS_DEVICE":
                return render_template("alert.html")

            return redirect(url_for('otp_verify'))

        else:
            return "<h3>❌ Invalid Username or Password</h3>"

    return render_template("login.html")

# ================= OTP VERIFY =================
@app.route('/otp', methods=['GET','POST'])
def otp_verify():

    if 'otp' not in session:
        return redirect('/')

    if request.method == 'POST':

        user_otp = request.form['otp']
        stored_otp = session['otp']
        otp_time = session['otp_time']
        user_id = session['user_id']

        conn = sqlite3.connect(DB)
        cur = conn.cursor()

        # latest login record
        cur.execute("""
        SELECT id, attempts FROM login_logs
        WHERE user_id=?
        ORDER BY id DESC LIMIT 1
        """, (user_id,))
        log_id, attempts = cur.fetchone()

        # OTP expired
        if time.time() - otp_time > 60:
            cur.execute("UPDATE login_logs SET status='EXPIRED' WHERE id=?", (log_id,))
            conn.commit()
            conn.close()
            session.clear()
            return "<h3>❌ OTP Expired</h3>"

        # WRONG OTP
        if user_otp != stored_otp:
            attempts += 1
            cur.execute("UPDATE login_logs SET attempts=? WHERE id=?", (attempts, log_id))

            if attempts >= 3:
                cur.execute("UPDATE login_logs SET status='BLOCKED' WHERE id=?", (log_id,))
                conn.commit()
                conn.close()
                session.clear()
                return "<h3>🚫 Account Blocked (Multiple Wrong OTP)</h3>"

            conn.commit()
            conn.close()
            return "<h3>⚠ Wrong OTP</h3>"

        # CORRECT OTP
        cur.execute("""
        UPDATE login_logs
        SET status='SAFE_LOGIN', attempts=0
        WHERE id=?
        """, (log_id,))

        conn.commit()
        conn.close()
        session.clear()

        return render_template("dashboard.html")

    return render_template("otp.html")

# ================= HISTORY =================
@app.route('/history')
def history():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("""
    SELECT login_time, ip, device, status
    FROM login_logs
    ORDER BY id DESC
    """)
    logs = cur.fetchall()
    conn.close()

    return render_template("history.html", logs=logs)

# ================= ANALYSIS =================
@app.route('/analysis')
def analysis():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("SELECT login_time FROM login_logs")
    times = cur.fetchall()
    conn.close()

    morning = afternoon = evening = night = 0

    for t in times:
        hour = int(t[0].split(" ")[1].split(":")[0])

        if 5 <= hour < 12:
            morning += 1
        elif 12 <= hour < 17:
            afternoon += 1
        elif 17 <= hour < 21:
            evening += 1
        else:
            night += 1

    return render_template("analysis.html",
                           morning=morning,
                           afternoon=afternoon,
                           evening=evening,
                           night=night)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000,debug=True)
