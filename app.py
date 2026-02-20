"""
MediCare Plus — Hospital Management System
Production build: reads config from environment variables, never from hard-coded values.
Compatible with Railway, Render, PythonAnywhere, and gunicorn.
"""

from flask import Flask, render_template, request, jsonify, session
import sqlite3, os, hashlib, secrets, logging
from datetime import date, datetime, timedelta

# Load .env when running locally (python-dotenv is in requirements.txt)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Email imports
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import threading

# ─────────────────────────────────────────────────────────────────────────────
#  ALL sensitive settings come from environment variables.
#  Set them in the Railway dashboard → Variables tab.
#  For local dev, copy .env.example → .env and fill in values.
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# On Railway, DB lives on the persistent Volume mounted at /data
_db_env = os.environ.get('DB_PATH', '').strip()
DB_PATH = _db_env if _db_env else os.path.join(BASE_DIR, 'hospital.db')

# Secret key — MUST be set as env var. Railway auto-generates one if you use the template.
_secret = os.environ.get('SECRET_KEY', '').strip()
if not _secret:
    logging.warning("SECRET_KEY not set — using a temporary key. Set it in Railway Variables tab.")
    _secret = secrets.token_hex(32)   # random each restart; sessions won't survive restarts

app = Flask(__name__)
app.secret_key = _secret

# Secure session cookie settings
app.config.update(
    SESSION_COOKIE_HTTPONLY   = True,
    SESSION_COOKIE_SAMESITE   = 'Lax',
    SESSION_COOKIE_SECURE     = (os.environ.get('FLASK_ENV') == 'production'),
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8),
)

# Hospital branding — safe to set via env vars or leave as defaults
HOSPITAL_NAME  = os.environ.get('HOSPITAL_NAME',  'MediCare Plus Hospital')
HOSPITAL_PHONE = os.environ.get('HOSPITAL_PHONE', '+1-800-MEDICARE')

MAIL_HOST = 'smtp.gmail.com'
MAIL_PORT = 587

# ── Security headers on every response ───────────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options']        = 'SAMEORIGIN'
    response.headers['X-XSS-Protection']       = '1; mode=block'
    response.headers['Referrer-Policy']        = 'strict-origin-when-cross-origin'
    response.headers.pop('Server', None)
    return response

EMAIL_CONFIG_FILE = os.path.join(os.path.dirname(DB_PATH), 'email_config.json')

def load_email_config():
    """Load email config from file, fallback to defaults."""
    defaults = {'enabled': False, 'username': '', 'password': '', 'provider': 'gmail'}
    try:
        if os.path.exists(EMAIL_CONFIG_FILE):
            import json
            with open(EMAIL_CONFIG_FILE) as f:
                saved = json.load(f)
                defaults.update(saved)
    except:
        pass
    return defaults

def save_email_config(cfg):
    import json
    with open(EMAIL_CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)

def get_mail_settings():
    cfg = load_email_config()
    return cfg.get('username',''), cfg.get('password',''), cfg.get('enabled', False)
# ─────────────────────────────────────────────────────────────────────────────

# ── DB helpers ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def query(sql, params=(), one=False):
    with get_db() as conn:
        cur  = conn.execute(sql, params)
        rows = cur.fetchall()
        return (dict(rows[0]) if rows else None) if one else [dict(r) for r in rows]

def execute(sql, params=()):
    with get_db() as conn:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def logged_in():
    return 'user_id' in session

def require_login():
    if not logged_in():
        return jsonify({'error': 'Not authenticated', 'login_required': True}), 401
    return None

# ── Email ─────────────────────────────────────────────────────────────────────

def send_email_async(to_email, subject, html_body):
    """Send email in background thread so it doesn't slow down the API."""
    username, password, enabled = get_mail_settings()
    if not enabled or not username or not password:
        print(f"⚠️  Email skipped — not configured. Go to Admin → Email Settings to set up.")
        return
    if not to_email or '@' not in to_email:
        print(f"⚠️  Email skipped — invalid recipient: {to_email}")
        return
    def _send():
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From']    = f'{HOSPITAL_NAME} <{username}>'
            msg['To']      = to_email
            msg.attach(MIMEText(html_body, 'html'))
            with smtplib.SMTP(MAIL_HOST, MAIL_PORT, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.login(username, password)
                server.sendmail(username, to_email, msg.as_string())
            print(f"✅ Email sent to {to_email}")
        except smtplib.SMTPAuthenticationError:
            print("❌ Gmail authentication failed. Check username/password in Admin → Email Settings.")
        except smtplib.SMTPException as e:
            print(f"❌ SMTP error: {e}")
        except Exception as e:
            print(f"❌ Email error: {e}")
    threading.Thread(target=_send, daemon=True).start()

def build_confirmation_email(patient_name, doctor_name, department, appt_date, appt_time, reason, appt_id):
    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f6f9;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f9;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:white;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.1);">
        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#1a1f36,#2d3348);padding:36px 40px;text-align:center;">
          <div style="font-size:36px;margin-bottom:8px;">🏥</div>
          <h1 style="color:white;margin:0;font-size:26px;font-weight:700;">{HOSPITAL_NAME}</h1>
          <p style="color:rgba(255,255,255,.7);margin:8px 0 0;font-size:14px;">Appointment Confirmation</p>
        </td></tr>
        <!-- Green banner -->
        <tr><td style="background:#00C853;padding:16px 40px;text-align:center;">
          <p style="color:white;font-weight:700;font-size:17px;margin:0;">✅ Your Appointment is Confirmed!</p>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:36px 40px;">
          <p style="color:#374151;font-size:16px;margin:0 0 24px;">Dear <strong>{patient_name}</strong>,</p>
          <p style="color:#6B7280;font-size:15px;margin:0 0 28px;">
            Your appointment has been successfully confirmed. Please find the details below.
          </p>
          <!-- Appointment card -->
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;margin-bottom:28px;">
            <tr><td style="background:#1a1f36;padding:14px 20px;">
              <p style="color:white;font-weight:700;margin:0;font-size:14px;">📋 Appointment Details</p>
            </td></tr>
            <tr><td style="padding:20px;">
              <table width="100%" cellpadding="8" cellspacing="0">
                <tr>
                  <td style="color:#6B7280;font-size:13px;width:140px;">🔖 Appointment ID</td>
                  <td style="color:#1a1f36;font-weight:700;font-size:13px;">#APT-{str(appt_id).zfill(3)}</td>
                </tr>
                <tr style="background:white;border-radius:6px;">
                  <td style="color:#6B7280;font-size:13px;">👨‍⚕️ Doctor</td>
                  <td style="color:#1a1f36;font-weight:600;font-size:13px;">{doctor_name}</td>
                </tr>
                <tr>
                  <td style="color:#6B7280;font-size:13px;">🏥 Department</td>
                  <td style="color:#1a1f36;font-weight:600;font-size:13px;">{department}</td>
                </tr>
                <tr style="background:white;border-radius:6px;">
                  <td style="color:#6B7280;font-size:13px;">📅 Date</td>
                  <td style="color:#1a1f36;font-weight:600;font-size:13px;">{appt_date}</td>
                </tr>
                <tr>
                  <td style="color:#6B7280;font-size:13px;">🕐 Time</td>
                  <td style="color:#1a1f36;font-weight:600;font-size:13px;">{appt_time}</td>
                </tr>
                <tr style="background:white;border-radius:6px;">
                  <td style="color:#6B7280;font-size:13px;">📝 Reason</td>
                  <td style="color:#1a1f36;font-weight:600;font-size:13px;">{reason or 'General Consultation'}</td>
                </tr>
              </table>
            </td></tr>
          </table>
          <!-- What to bring -->
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff8e1;border:1px solid #FFB800;border-radius:12px;padding:20px;margin-bottom:28px;">
            <tr><td style="padding:16px 20px;">
              <p style="color:#92400e;font-weight:700;margin:0 0 10px;">📌 What to bring:</p>
              <ul style="color:#78350f;font-size:13px;margin:0;padding-left:20px;line-height:1.9;">
                <li>Valid government-issued ID</li>
                <li>Insurance card (if applicable)</li>
                <li>Previous medical records / test reports</li>
                <li>List of current medications</li>
              </ul>
            </td></tr>
          </table>
          <p style="color:#6B7280;font-size:14px;">
            Please arrive <strong>15 minutes early</strong>. To cancel or reschedule, 
            contact us at <strong>{HOSPITAL_PHONE}</strong>.
          </p>
        </td></tr>
        <!-- Footer -->
        <tr><td style="background:#f8fafc;padding:24px 40px;text-align:center;border-top:1px solid #e5e7eb;">
          <p style="color:#9CA3AF;font-size:12px;margin:0;">
            {HOSPITAL_NAME} · This is an automated message, please do not reply.<br>
            © {datetime.now().year} {HOSPITAL_NAME}. All rights reserved.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

def build_status_change_email(patient_name, doctor_name, department, appt_date, appt_time, new_status, appt_id):
    status_cfg = {
        'Confirmed': ('✅', '#00C853', 'Your appointment has been confirmed.'),
        'Completed': ('🏁', '#0066FF', 'Your appointment is marked as completed. Thank you for visiting us.'),
        'Cancelled': ('❌', '#FF6B6B', 'Your appointment has been cancelled. Please contact us to reschedule.'),
        'No-Show':   ('🚫', '#9E9E9E', 'You were marked as a no-show. Please contact us to book a new appointment.'),
        'Pending':   ('⏳', '#FFB800', 'Your appointment is pending confirmation.'),
    }
    icon, color, msg = status_cfg.get(new_status, ('📋', '#1a1f36', 'Your appointment status has been updated.'))
    return f"""
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f4f6f9;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f9;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:white;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.1);">
        <tr><td style="background:linear-gradient(135deg,#1a1f36,#2d3348);padding:28px 40px;text-align:center;">
          <h1 style="color:white;margin:0;font-size:22px;">🏥 {HOSPITAL_NAME}</h1>
        </td></tr>
        <tr><td style="background:{color};padding:14px 40px;text-align:center;">
          <p style="color:white;font-weight:700;font-size:16px;margin:0;">{icon} Appointment Status Update: {new_status}</p>
        </td></tr>
        <tr><td style="padding:32px 40px;">
          <p style="color:#374151;font-size:16px;">Dear <strong>{patient_name}</strong>,</p>
          <p style="color:#6B7280;font-size:15px;">{msg}</p>
          <table width="100%" cellpadding="8" style="background:#f8fafc;border-radius:12px;border:1px solid #e5e7eb;margin:20px 0;">
            <tr><td style="color:#6B7280;font-size:13px;">Appointment ID</td><td style="font-weight:700;color:#1a1f36;">#APT-{str(appt_id).zfill(3)}</td></tr>
            <tr><td style="color:#6B7280;font-size:13px;">Doctor</td><td style="font-weight:600;color:#1a1f36;">{doctor_name}</td></tr>
            <tr><td style="color:#6B7280;font-size:13px;">Date &amp; Time</td><td style="font-weight:600;color:#1a1f36;">{appt_date} at {appt_time}</td></tr>
            <tr><td style="color:#6B7280;font-size:13px;">New Status</td><td><strong style="color:{color};">{icon} {new_status}</strong></td></tr>
          </table>
          <p style="color:#6B7280;font-size:14px;">Questions? Call us at <strong>{HOSPITAL_PHONE}</strong>.</p>
        </td></tr>
        <tr><td style="background:#f8fafc;padding:20px 40px;text-align:center;border-top:1px solid #e5e7eb;">
          <p style="color:#9CA3AF;font-size:12px;margin:0;">© {datetime.now().year} {HOSPITAL_NAME}</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

def build_service_booking_email(patient_name, service_name, service_type, booking_date, booking_time, amount, booking_id, preparation=''):
    """Generic email for lab test and radiology bookings on confirmation."""
    icon = '🔬' if service_type == 'Laboratory' else '📡'
    color = '#00C853' if service_type == 'Laboratory' else '#0066FF'
    prefix = 'LAB' if service_type == 'Laboratory' else 'RAD'
    prep_section = ''
    if preparation:
        prep_section = f"""
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff8e1;border:1px solid #FFB800;border-radius:12px;margin-bottom:24px;">
            <tr><td style="padding:16px 20px;">
              <p style="color:#92400e;font-weight:700;margin:0 0 8px;">📋 Preparation Instructions:</p>
              <p style="color:#78350f;font-size:13px;margin:0;line-height:1.8;">{preparation}</p>
            </td></tr>
          </table>"""
    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f6f9;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f9;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:white;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.1);">
        <tr><td style="background:linear-gradient(135deg,#1a1f36,#2d3348);padding:36px 40px;text-align:center;">
          <div style="font-size:36px;margin-bottom:8px;">🏥</div>
          <h1 style="color:white;margin:0;font-size:26px;font-weight:700;">{HOSPITAL_NAME}</h1>
          <p style="color:rgba(255,255,255,.7);margin:8px 0 0;font-size:14px;">{service_type} Booking Confirmation</p>
        </td></tr>
        <tr><td style="background:{color};padding:16px 40px;text-align:center;">
          <p style="color:white;font-weight:700;font-size:17px;margin:0;">{icon} Your {service_type} Booking is Confirmed!</p>
        </td></tr>
        <tr><td style="padding:36px 40px;">
          <p style="color:#374151;font-size:16px;margin:0 0 24px;">Dear <strong>{patient_name}</strong>,</p>
          <p style="color:#6B7280;font-size:15px;margin:0 0 28px;">
            Your {service_type.lower()} booking has been confirmed. Please find the details below.
          </p>
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;margin-bottom:24px;">
            <tr><td style="background:#1a1f36;padding:14px 20px;">
              <p style="color:white;font-weight:700;margin:0;font-size:14px;">{icon} Booking Details</p>
            </td></tr>
            <tr><td style="padding:20px;">
              <table width="100%" cellpadding="8" cellspacing="0">
                <tr><td style="color:#6B7280;font-size:13px;width:160px;">🔖 Booking ID</td>
                    <td style="color:#1a1f36;font-weight:700;font-size:13px;">#{prefix}-{str(booking_id).zfill(4)}</td></tr>
                <tr style="background:white;"><td style="color:#6B7280;font-size:13px;">📋 Service</td>
                    <td style="color:#1a1f36;font-weight:600;font-size:13px;">{service_name}</td></tr>
                <tr><td style="color:#6B7280;font-size:13px;">📅 Date</td>
                    <td style="color:#1a1f36;font-weight:600;font-size:13px;">{booking_date}</td></tr>
                <tr style="background:white;"><td style="color:#6B7280;font-size:13px;">🕐 Time</td>
                    <td style="color:#1a1f36;font-weight:600;font-size:13px;">{booking_time}</td></tr>
                <tr><td style="color:#6B7280;font-size:13px;">💰 Amount</td>
                    <td style="color:#1a1f36;font-weight:700;font-size:14px;">₹{int(amount):,}</td></tr>
              </table>
            </td></tr>
          </table>
          {prep_section}
          <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:12px;margin-bottom:24px;">
            <tr><td style="padding:16px 20px;">
              <p style="color:#166534;font-weight:700;margin:0 0 8px;">📌 Please note:</p>
              <ul style="color:#15803d;font-size:13px;margin:0;padding-left:20px;line-height:1.9;">
                <li>Arrive <strong>10 minutes before</strong> your scheduled time</li>
                <li>Carry a valid government-issued photo ID</li>
                <li>Bring this confirmation email or booking ID</li>
                <li>Payment of <strong>₹{int(amount):,}</strong> is due at the time of service</li>
              </ul>
            </td></tr>
          </table>
          <p style="color:#6B7280;font-size:14px;">
            Need to reschedule or cancel? Contact us at <strong>{HOSPITAL_PHONE}</strong>.
          </p>
        </td></tr>
        <tr><td style="background:#f8fafc;padding:24px 40px;text-align:center;border-top:1px solid #e5e7eb;">
          <p style="color:#9CA3AF;font-size:12px;margin:0;">
            {HOSPITAL_NAME} · This is an automated message, please do not reply.<br>
            © {datetime.now().year} {HOSPITAL_NAME}. All rights reserved.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


def build_service_status_email(patient_name, service_name, service_type, booking_date, new_status, booking_id, amount):
    """Email sent when lab/radiology booking status changes (Confirmed/Completed/Cancelled)."""
    prefix  = 'LAB' if service_type == 'Laboratory' else 'RAD'
    status_cfg = {
        'Confirmed': ('✅', '#00C853', 'Your booking has been confirmed. Please arrive on time.'),
        'Completed': ('🏁', '#0066FF', 'Your test/scan is complete. Results will be shared soon.'),
        'Cancelled': ('❌', '#FF6B6B', 'Your booking has been cancelled. Please contact us to reschedule.'),
        'Pending':   ('⏳', '#FFB800', 'Your booking is pending confirmation by our team.'),
    }
    icon, color, msg = status_cfg.get(new_status, ('📋', '#1a1f36', 'Your booking status has been updated.'))
    return f"""
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f4f6f9;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f9;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:white;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.1);">
        <tr><td style="background:linear-gradient(135deg,#1a1f36,#2d3348);padding:28px 40px;text-align:center;">
          <h1 style="color:white;margin:0;font-size:22px;">🏥 {HOSPITAL_NAME}</h1>
        </td></tr>
        <tr><td style="background:{color};padding:14px 40px;text-align:center;">
          <p style="color:white;font-weight:700;font-size:16px;margin:0;">{icon} Booking Status: {new_status}</p>
        </td></tr>
        <tr><td style="padding:32px 40px;">
          <p style="color:#374151;font-size:16px;">Dear <strong>{patient_name}</strong>,</p>
          <p style="color:#6B7280;font-size:15px;">{msg}</p>
          <table width="100%" cellpadding="8" style="background:#f8fafc;border-radius:12px;border:1px solid #e5e7eb;margin:20px 0;">
            <tr><td style="color:#6B7280;font-size:13px;">Booking ID</td>
                <td style="font-weight:700;color:#1a1f36;">#{prefix}-{str(booking_id).zfill(4)}</td></tr>
            <tr><td style="color:#6B7280;font-size:13px;">Service</td>
                <td style="font-weight:600;color:#1a1f36;">{service_name}</td></tr>
            <tr><td style="color:#6B7280;font-size:13px;">Date</td>
                <td style="font-weight:600;color:#1a1f36;">{booking_date}</td></tr>
            <tr><td style="color:#6B7280;font-size:13px;">Amount</td>
                <td style="font-weight:700;color:#1a1f36;">₹{int(amount):,}</td></tr>
            <tr><td style="color:#6B7280;font-size:13px;">New Status</td>
                <td><strong style="color:{color};">{icon} {new_status}</strong></td></tr>
          </table>
          <p style="color:#6B7280;font-size:14px;">Questions? Call us at <strong>{HOSPITAL_PHONE}</strong>.</p>
        </td></tr>
        <tr><td style="background:#f8fafc;padding:20px 40px;text-align:center;border-top:1px solid #e5e7eb;">
          <p style="color:#9CA3AF;font-size:12px;margin:0;">© {datetime.now().year} {HOSPITAL_NAME}</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL, plain_password TEXT,
    role TEXT DEFAULT 'staff',
    full_name TEXT, doctor_id INTEGER REFERENCES doctors(id),
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS departments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
    icon TEXT DEFAULT 'hospital', description TEXT,
    hidden INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS doctors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, specialization TEXT NOT NULL,
    department TEXT NOT NULL, experience INTEGER DEFAULT 0,
    contact TEXT, email TEXT, qualification TEXT, available INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL, last_name TEXT NOT NULL,
    date_of_birth TEXT NOT NULL, gender TEXT NOT NULL,
    blood_group TEXT, contact TEXT NOT NULL,
    email TEXT, address TEXT, emergency_contact TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL REFERENCES patients(id),
    doctor_id  INTEGER NOT NULL REFERENCES doctors(id),
    appointment_date TEXT NOT NULL, appointment_time TEXT NOT NULL,
    reason TEXT, status TEXT DEFAULT 'Pending',
    amount REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS lab_tests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, category TEXT NOT NULL,
    description TEXT, price REAL DEFAULT 0,
    turnaround TEXT DEFAULT '24 hours',
    active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS lab_bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_name TEXT NOT NULL, patient_contact TEXT NOT NULL,
    patient_email TEXT, test_id INTEGER REFERENCES lab_tests(id),
    test_name TEXT NOT NULL, booking_date TEXT NOT NULL,
    booking_time TEXT NOT NULL, status TEXT DEFAULT 'Pending',
    notes TEXT, amount REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS medicines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, category TEXT NOT NULL,
    description TEXT, unit_price REAL DEFAULT 0,
    stock_qty INTEGER DEFAULT 0, reorder_level INTEGER DEFAULT 10,
    supplier TEXT, expiry_date TEXT,
    active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS radiology_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, modality TEXT NOT NULL,
    description TEXT, price REAL DEFAULT 0,
    preparation TEXT, duration_minutes INTEGER DEFAULT 30,
    active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS radiology_bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_name TEXT NOT NULL, patient_contact TEXT NOT NULL,
    patient_email TEXT, service_id INTEGER REFERENCES radiology_services(id),
    service_name TEXT NOT NULL, booking_date TEXT NOT NULL,
    booking_time TEXT NOT NULL, status TEXT DEFAULT 'Pending',
    notes TEXT, amount REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS admissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL REFERENCES patients(id),
    doctor_id  INTEGER REFERENCES doctors(id),
    ward       TEXT NOT NULL,
    room_no    TEXT,
    bed_no     TEXT,
    admit_date TEXT NOT NULL,
    discharge_date TEXT,
    diagnosis  TEXT,
    treatment  TEXT,
    amount     REAL DEFAULT 0,
    status     TEXT DEFAULT 'Admitted',
    notes      TEXT,
    admitted_by INTEGER REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now'))
);
"""

# ── Seed ──────────────────────────────────────────────────────────────────────

DEPARTMENTS_SEED = [
    ("cardiology","Cardiology","Heart & cardiovascular care"),
    ("neurology","Neurology","Brain & nervous system care"),
    ("orthopedics","Orthopedics","Bone, joint & spine care"),
    ("pediatrics","Pediatrics","Child healthcare"),
    ("pulmonology","Pulmonology","Respiratory care"),
    ("hematology","Hematology","Blood disorders"),
    ("oncology","Oncology","Cancer care"),
    ("gynecology","Gynecology","Women's health"),
    ("dermatology","Dermatology","Skin, hair & nail care"),
    ("psychiatry","Psychiatry","Mental health care"),
    ("ent","ENT","Ear, nose & throat"),
    ("urology","Urology","Urinary & renal care"),
]
DOCTORS_SEED = [
    ("Dr. Sarah Wilson","Interventional Cardiologist","Cardiology",15,"MD, FACC"),
    ("Dr. James Carter","Cardiac Surgeon","Cardiology",18,"MD, FACS"),
    ("Dr. Emily Roberts","Electrophysiologist","Cardiology",12,"MD"),
    ("Dr. Michael Chen","Neurologist","Neurology",12,"MD, PhD"),
    ("Dr. Patricia Lee","Stroke Specialist","Neurology",14,"MD"),
    ("Dr. Robert Kim","Movement Disorder Specialist","Neurology",10,"MD"),
    ("Dr. David Martinez","Orthopedic Surgeon","Orthopedics",16,"MD, FAAOS"),
    ("Dr. Jennifer White","Sports Medicine","Orthopedics",11,"MD"),
    ("Dr. Thomas Anderson","Spine Specialist","Orthopedics",20,"MD, PhD"),
    ("Dr. Lisa Brown","Pediatrician","Pediatrics",13,"MD, FAAP"),
    ("Dr. Mark Johnson","Neonatologist","Pediatrics",15,"MD"),
    ("Dr. Rachel Green","Pediatric Allergist","Pediatrics",9,"MD"),
    ("Dr. Amanda Foster","Pulmonologist","Pulmonology",11,"MD, FCCP"),
    ("Dr. Christopher Lee","Critical Care Specialist","Pulmonology",16,"MD"),
    ("Dr. Maria Garcia","Sleep Medicine","Pulmonology",8,"MD"),
    ("Dr. Steven Park","Hematologist","Hematology",14,"MD, FACP"),
    ("Dr. Nicole Davis","Hematology-Oncologist","Hematology",17,"MD"),
    ("Dr. Kevin Wright","Coagulation Specialist","Hematology",12,"MD"),
    ("Dr. Susan Hall","Medical Oncologist","Oncology",18,"MD"),
    ("Dr. Brian Turner","Radiation Oncologist","Oncology",15,"MD"),
    ("Dr. Diana Price","Surgical Oncologist","Oncology",20,"MD, FACS"),
    ("Dr. Rachel Adams","OB/GYN","Gynecology",14,"MD"),
    ("Dr. Karen Adams","Maternal-Fetal Medicine","Gynecology",16,"MD"),
    ("Dr. Helen Moore","Reproductive Endocrinologist","Gynecology",13,"MD, PhD"),
    ("Dr. Olivia Scott","Dermatologist","Dermatology",10,"MD"),
    ("Dr. Nathan Bailey","Cosmetic Dermatologist","Dermatology",12,"MD"),
    ("Dr. Mia Cooper","Pediatric Dermatologist","Dermatology",9,"MD"),
    ("Dr. Alan Hughes","Psychiatrist","Psychiatry",19,"MD"),
    ("Dr. Sophie Reed","Child Psychiatrist","Psychiatry",11,"MD"),
    ("Dr. George Nelson","Addiction Specialist","Psychiatry",15,"MD"),
    ("Dr. Fiona Grant","Otolaryngologist","ENT",13,"MD"),
    ("Dr. James Collins","Head & Neck Surgeon","ENT",16,"MD, FACS"),
    ("Dr. Laura Evans","Audiologist","ENT",8,"AuD"),
    ("Dr. Charles Webb","Urologist","Urology",17,"MD"),
    ("Dr. Emma Powell","Pediatric Urologist","Urology",12,"MD"),
    ("Dr. Henry Long","Renal Transplant Specialist","Urology",20,"MD, FACS"),
]
PATIENTS_SEED = [
    ("John","Anderson","1985-03-12","Male","A+","+1-555-1001","john@email.com"),
    ("Emma","Thompson","1992-07-25","Female","O-","+1-555-1002","emma@email.com"),
    ("Robert","Martinez","1978-11-08","Male","B+","+1-555-1003","robert@email.com"),
    ("Maria","Garcia","1995-04-17","Female","AB+","+1-555-1004","maria@email.com"),
    ("David","Lee","1988-09-30","Male","O+","+1-555-1005","david@email.com"),
]

LAB_TESTS_SEED = [
    # ── Blood Tests (12 records) ─────────────────────────────────────────────
    ("Complete Blood Count (CBC)","Blood Test","Measures red & white blood cells, platelets and hemoglobin levels. Essential screening test.",350,  "24 hours"),
    ("Blood Glucose — Fasting","Blood Test","Diagnoses diabetes and pre-diabetes. Requires 8 hours fasting before sample collection.",180,  "4 hours"),
    ("Blood Glucose — Post Prandial","Blood Test","Measures blood sugar 2 hours after a meal to monitor diabetes control.",180,  "4 hours"),
    ("Lipid Profile","Blood Test","Measures total cholesterol, triglycerides, HDL, LDL and VLDL levels.",550,  "24 hours"),
    ("Liver Function Test (LFT)","Blood Test","Comprehensive liver health panel — ALT, AST, ALP, bilirubin, albumin.",600,  "24 hours"),
    ("Kidney Function Test (KFT)","Blood Test","Creatinine, urea, uric acid, BUN and electrolytes for renal assessment.",650,  "24 hours"),
    ("HbA1c (Glycated Haemoglobin)","Blood Test","Reflects 3-month average blood sugar level. Key diabetes management test.",450,  "24 hours"),
    ("ESR (Erythrocyte Sedimentation Rate)","Blood Test","Non-specific inflammation marker. Elevated in infections, autoimmune disorders.",150,  "2 hours"),
    ("CRP (C-Reactive Protein)","Blood Test","Acute-phase protein elevated during infection, inflammation and tissue injury.",350,  "24 hours"),
    ("Iron Studies (Serum Iron, TIBC, Ferritin)","Blood Test","Comprehensive iron status panel for anaemia diagnosis and monitoring.",750,  "48 hours"),
    ("Vitamin B12 & Folic Acid","Blood Test","Detects deficiency causing megaloblastic anaemia and neurological symptoms.",850,  "48 hours"),
    ("Vitamin D3 (25-OH)","Blood Test","Measures vitamin D status. Deficiency linked to bone loss and immunity issues.",900,  "48 hours"),

    # ── Urine Tests (8 records) ──────────────────────────────────────────────
    ("Urine Routine & Microscopy","Urine Test","Physical, chemical and microscopic examination for kidney and bladder health.",200,  "2 hours"),
    ("Urine Culture & Sensitivity","Urine Test","Identifies bacteria causing UTI and determines appropriate antibiotic therapy.",600,  "72 hours"),
    ("24-Hour Urine Protein","Urine Test","Quantifies protein loss over 24 hours. Used in kidney disease monitoring.",450,  "24 hours"),
    ("Urine Microalbumin","Urine Test","Early marker of diabetic nephropathy and hypertensive kidney damage.",500,  "24 hours"),
    ("Urine Creatinine Clearance","Urine Test","Estimates glomerular filtration rate (GFR) to assess kidney function.",400,  "24 hours"),
    ("Urine Pregnancy Test (Quantitative HCG)","Urine Test","Detects and measures HCG hormone to confirm and monitor early pregnancy.",250,  "1 hour"),
    ("Urine Bilirubin & Urobilinogen","Urine Test","Detects liver disease and haemolytic anaemia through urine metabolites.",150,  "2 hours"),
    ("Urine Drug Screen (5-Panel)","Urine Test","Screens for opioids, cocaine, amphetamines, cannabis and benzodiazepines.",1200, "6 hours"),

    # ── Microbiology (6 records) ─────────────────────────────────────────────
    ("Blood Culture & Sensitivity","Microbiology","Detects bacteria or fungi in blood. Essential for sepsis diagnosis.",900,  "5 days"),
    ("Sputum Culture & Sensitivity","Microbiology","Identifies respiratory pathogens including TB, pneumonia organisms.",650,  "3 days"),
    ("Throat Swab Culture","Microbiology","Detects Group A Streptococcus and other throat pathogens.",500,  "48 hours"),
    ("Wound Swab Culture","Microbiology","Identifies infecting organisms in wounds and determines antibiotic sensitivity.",550,  "3 days"),
    ("Stool Culture & Sensitivity","Microbiology","Identifies bacterial pathogens causing gastroenteritis and diarrhoea.",600,  "3 days"),
    ("AFB Smear & Culture (TB)","Microbiology","Acid-fast bacilli detection for tuberculosis diagnosis. Includes Ziehl-Neelsen stain.",800,  "6 weeks"),

    # ── Stool Tests (4 records) ──────────────────────────────────────────────
    ("Stool Routine & Microscopy","Stool Test","Detects parasites, ova, cysts and occult blood. General GI health screen.",200,  "24 hours"),
    ("Stool Occult Blood (FOB)","Stool Test","Detects hidden blood in stool — screening for colorectal cancer and GI bleeding.",250,  "24 hours"),
    ("H. Pylori Antigen (Stool)","Stool Test","Non-invasive detection of Helicobacter pylori causing peptic ulcers.",650,  "24 hours"),
    ("Stool Fat (Sudan Stain)","Stool Test","Qualitative fat detection for malabsorption syndromes and pancreatic exocrine insufficiency.",350,  "24 hours"),

    # ── Serology (8 records) ─────────────────────────────────────────────────
    ("HIV 1 & 2 Antibody Test (ELISA)","Serology","Highly sensitive screening test for HIV infection.",400,  "24 hours"),
    ("Hepatitis B Surface Antigen (HBsAg)","Serology","Detects active Hepatitis B infection. Recommended for all adults.",400,  "24 hours"),
    ("Hepatitis C Antibody (Anti-HCV)","Serology","Screens for Hepatitis C virus exposure and infection.",450,  "24 hours"),
    ("Widal Test (Typhoid)","Serology","Detects antibodies against Salmonella typhi causing typhoid fever.",300,  "24 hours"),
    ("Dengue NS1 Antigen + IgG / IgM","Serology","Rapid differentiation of early (NS1) and late (IgG/IgM) dengue infection.",750,  "6 hours"),
    ("Malaria Antigen Test","Serology","Rapid test detecting P. vivax and P. falciparum antigens.",450,  "2 hours"),
    ("VDRL / RPR (Syphilis)","Serology","Non-treponemal screening test for syphilis and treatment monitoring.",300,  "24 hours"),
    ("RA Factor & Anti-CCP","Serology","Rheumatoid arthritis serological markers for diagnosis and prognosis.",950,  "48 hours"),

    # ── Hormone Tests (6 records) ────────────────────────────────────────────
    ("Thyroid Profile — T3, T4, TSH","Hormone Test","Complete thyroid function assessment. Diagnoses hypo/hyperthyroidism.",800,  "48 hours"),
    ("Prolactin","Hormone Test","Measures prolactin levels. Elevated in pituitary tumours, infertility workup.",600,  "48 hours"),
    ("FSH & LH","Hormone Test","Gonadotropins for fertility evaluation, menstrual disorder assessment.",700,  "48 hours"),
    ("Testosterone (Total & Free)","Hormone Test","Male hypogonadism, infertility and PCOS workup.",900,  "48 hours"),
    ("Cortisol (Morning)","Hormone Test","Adrenal function assessment. Elevated in Cushing's syndrome.",650,  "48 hours"),
    ("Insulin & C-Peptide","Hormone Test","Measures pancreatic beta-cell insulin secretion. Differentiates diabetes types.",1100, "48 hours"),

    # ── Pathology (4 records) ────────────────────────────────────────────────
    ("Biopsy — Small Tissue (Histopathology)","Pathology","Microscopic tissue examination for cancer diagnosis — skin, lymph node, etc.",2500, "7 days"),
    ("Biopsy — Large Tissue (Histopathology)","Pathology","Detailed surgical specimen analysis for staging and treatment planning.",4500, "10 days"),
    ("FNAC (Fine Needle Aspiration Cytology)","Pathology","Minimally invasive cell sampling from lumps, lymph nodes or thyroid.",1800, "5 days"),
    ("Pap Smear (Cervical Cytology)","Cytology","Cervical cancer screening and HPV-related cell change detection.",850,  "5 days"),
]

MEDICINES_SEED = [
    ("Paracetamol 500mg (Strip of 10)","Analgesic","Pain reliever and fever reducer. First-line for mild to moderate pain.",22,   500,50,"Sun Pharma","2026-12-31"),
    ("Amoxicillin 500mg (Strip of 10)","Antibiotic","Broad-spectrum penicillin antibiotic for respiratory, ENT and skin infections.",85,   300,30,"Cipla","2026-06-30"),
    ("Metformin 500mg (Strip of 10)","Antidiabetic","First-line oral medication for type 2 diabetes management.",38,   400,40,"Mankind","2027-01-31"),
    ("Amlodipine 5mg (Strip of 10)","Antihypertensive","Calcium channel blocker for hypertension and angina.",45,   350,35,"Torrent","2027-03-31"),
    ("Atorvastatin 10mg (Strip of 10)","Statin","Reduces LDL cholesterol and cardiovascular event risk.",95,   250,25,"Ranbaxy","2026-11-30"),
    ("Omeprazole 20mg (Strip of 10)","PPI","Proton pump inhibitor for GERD, peptic ulcer disease and acid reflux.",55,   280,30,"Zydus","2027-02-28"),
    ("Cetirizine 10mg (Strip of 10)","Antihistamine","Second-generation antihistamine for allergic rhinitis and urticaria.",30,   450,40,"Dr. Reddy's","2027-04-30"),
    ("Azithromycin 500mg (Strip of 3)","Antibiotic","Macrolide antibiotic for atypical pneumonia, pharyngitis and skin infections.",145,  150,20,"Cipla","2026-08-31"),
    ("Pantoprazole 40mg (Strip of 10)","PPI","Gastric acid suppressant for esophagitis and Zollinger-Ellison syndrome.",80,   220,25,"Abbott","2027-06-30"),
    ("Levothyroxine 50mcg (Strip of 30)","Thyroid","Synthetic thyroid hormone replacement for hypothyroidism.",90,   180,20,"Merck","2027-01-31"),
    ("Ibuprofen 400mg (Strip of 10)","NSAID","Anti-inflammatory analgesic for pain, fever and inflammatory conditions.",28,   380,40,"Sun Pharma","2026-10-31"),
    ("Aspirin 75mg (Strip of 14)","Antiplatelet","Low-dose antiplatelet for cardiac and stroke prevention.",22,   600,60,"Bayer","2027-05-31"),
    ("Insulin Glargine 100U/ml (Vial)","Antidiabetic","Long-acting basal insulin for type 1 and type 2 diabetes.",1200, 80, 10,"Novo Nordisk","2026-09-30"),
    ("Prednisolone 5mg (Strip of 10)","Corticosteroid","Systemic corticosteroid for inflammatory and autoimmune conditions.",42,   200,25,"Pfizer","2026-07-31"),
    ("Salbutamol Inhaler 100mcg (200 doses)","Bronchodilator","Short-acting beta-2 agonist reliever for acute asthma and COPD.",185,  120,15,"GSK","2026-12-31"),
    ("Clopidogrel 75mg (Strip of 10)","Antiplatelet","Prevents platelet aggregation post-MI, stroke and stent placement.",125,  160,20,"Lupin","2027-02-28"),
    ("Metoprolol 50mg (Strip of 10)","Beta Blocker","Cardioselective beta blocker for hypertension, angina and heart failure.",75,   190,20,"Intas","2027-03-31"),
    ("Doxycycline 100mg (Strip of 10)","Antibiotic","Broad-spectrum tetracycline for RTI, UTI, malaria prophylaxis.",95,   140,15,"Cipla","2026-11-30"),
    ("Fluconazole 150mg (Strip of 1)","Antifungal","Single-dose oral treatment for vaginal candidiasis and oral thrush.",65,   100,12,"Sun Pharma","2027-01-31"),
    ("Vitamin D3 60000 IU (Sachets x 4)","Supplement","Weekly cholecalciferol dose for vitamin D deficiency correction.",160,  300,30,"Cadila","2027-06-30"),
    ("Montelukast 10mg (Strip of 10)","Antiasthmatic","Leukotriene receptor antagonist for asthma and allergic rhinitis.",120,  200,25,"Cipla","2027-03-31"),
    ("Glimepiride 2mg (Strip of 10)","Antidiabetic","Sulfonylurea for type 2 diabetes — stimulates pancreatic insulin release.",55,   220,25,"Sanofi","2027-02-28"),
    ("Losartan 50mg (Strip of 10)","Antihypertensive","Angiotensin receptor blocker (ARB) for hypertension and diabetic nephropathy.",72,   260,30,"Dr. Reddy's","2027-04-30"),
    ("Ranitidine 150mg (Strip of 10)","Antacid","H2 blocker for peptic ulcers, GERD and Zollinger-Ellison syndrome.",28,   180,20,"Cipla","2026-12-31"),
    ("Tramadol 50mg (Strip of 10)","Analgesic","Opioid analgesic for moderate to severe pain management.",95,   150,15,"Wockhardt","2026-10-31"),
]

RADIOLOGY_SEED = [
    ("Chest X-Ray","X-Ray","Standard PA view radiograph for lungs, heart and bony thorax evaluation.",350,  "No special preparation required",15),
    ("Abdominal X-Ray","X-Ray","Evaluates bowel gas pattern, calculi and abdominal organ sizes.",400,  "No preparation required",15),
    ("Bone X-Ray — Single Region","X-Ray","Fracture detection, bone density and joint space assessment.",300,  "Remove all metal objects from the area",10),
    ("Skull X-Ray","X-Ray","Evaluates skull fractures, sinuses and intracranial calcifications.",350,  "Remove hair accessories and metal objects",10),
    ("Spine X-Ray (Cervical / Lumbar)","X-Ray","Vertebral alignment, disc spaces and degenerative changes assessment.",500,  "Remove metal objects; stand or lie as instructed",15),
    ("CT Scan — Head / Brain","CT Scan","Detailed brain parenchyma imaging for trauma, stroke and intracranial tumours.",3500, "Remove metal; contrast dye may be administered",20),
    ("CT Scan — Chest (HRCT)","CT Scan","High-resolution pulmonary imaging for ILD, nodules and COVID-19 assessment.",4000, "Fasting 4 hours if IV contrast is planned",25),
    ("CT Scan — Abdomen & Pelvis","CT Scan","Comprehensive abdominal organ and pelvic structure evaluation.",5000, "Fasting 4 hours; oral contrast required",30),
    ("CT Scan — KUB (Kidney Ureter Bladder)","CT Scan","Non-contrast scan for renal calculi, ureteric stones detection.",3000, "No preparation required for non-contrast",20),
    ("CT Angiography (CTA)","CT Scan","Vascular imaging for coronary artery disease, aortic aneurysm, PE.",6500, "IV access required; fasting 4 hours",40),
    ("MRI — Brain (with / without contrast)","MRI","Detailed soft tissue brain imaging for tumours, MS, epilepsy, dementia.",7500, "Remove all metal implants; MRI safety screening required",45),
    ("MRI — Spine (Lumbar / Cervical)","MRI","Disc herniation, spinal canal stenosis and cord compression evaluation.",7000, "Remove metal; inform radiographer of any implants",50),
    ("MRI — Knee","MRI","Ligament tears, meniscal injuries and cartilage damage assessment.",6500, "Remove knee prosthesis info; inform of implants",45),
    ("MRI — Shoulder","MRI","Rotator cuff tears, labral pathology and joint space evaluation.",6500, "Remove all metal; shoulder arthrography if planned",45),
    ("MRI — Abdomen (Liver / Pancreas)","MRI","Characterisation of liver lesions, MRCP for biliary tree imaging.",8500, "Fasting 4 hours; breath-hold sequences used",60),
    ("Ultrasound — Abdomen","Ultrasound","Liver, gallbladder, spleen, pancreas and kidney sonographic assessment.",700,  "Strict fasting 6 hours before the scan",20),
    ("Ultrasound — Pelvis (Transabdominal)","Ultrasound","Uterus, ovaries and bladder evaluation for gynaecological conditions.",700,  "Full bladder required — drink 1 litre, do not void",20),
    ("Ultrasound — Obstetric (Dating / Anomaly)","Ultrasound","Foetal growth, placenta, amniotic fluid and anomaly screening.",900,  "Full bladder for first trimester; empty for later trimesters",25),
    ("Ultrasound — Thyroid & Neck","Ultrasound","Thyroid nodule characterisation, lymph node and neck mass assessment.",700,  "No special preparation required",15),
    ("Colour Doppler — Peripheral Vessels","Ultrasound","Blood flow velocity and direction in leg veins and arteries (DVT, varicose veins).",1200, "Avoid smoking 2 hours before; comfortable clothing",30),
    ("Echocardiography (2D Echo)","Echocardiography","Cardiac structure and function including EF, valve and wall motion.",2500, "No preparation required; avoid heavy meals",30),
    ("Mammography (Bilateral)","Mammography","Bilateral breast cancer screening and diagnostic imaging.",1500, "No deodorant, powder or perfume on day of scan",20),
    ("DEXA Bone Density Scan","Bone Densitometry","BMD measurement for osteoporosis diagnosis and fracture risk stratification.",2000, "No calcium supplements 24 hours before; no contrast studies",20),
    ("PET-CT Scan","Nuclear Medicine","Whole-body metabolic imaging for cancer staging, recurrence detection.",18000,"Fasting 6 hours; blood sugar < 200 mg/dL; no exercise day before",90),
]

def generate_doctor_credentials(doctor_name, doctor_id):
    """Generate a username and password for a doctor based on their name and ID."""
    # Strip "Dr." prefix and generate slug: dr_sarahwilson
    clean = doctor_name.lower().replace('dr.','').replace('dr ','').strip()
    parts = clean.split()
    username = 'dr_' + ''.join(parts)  # e.g. dr_sarahwilson
    # Make unique if collision: append doctor_id
    existing = query("SELECT id FROM users WHERE username=?",(username,),one=True)
    if existing:
        username = f'dr_{parts[0]}{doctor_id}'
    # Password: first part of name + id, e.g. sarah#12
    password = f"{parts[0]}#{doctor_id}"
    return username, password

def create_doctor_user(doctor_id, doctor_name, doctor_email=None):
    """Create a user account for a doctor if one doesn't already exist."""
    existing = query("SELECT id FROM users WHERE doctor_id=?",(doctor_id,),one=True)
    if existing:
        return None
    username, password = generate_doctor_credentials(doctor_name, doctor_id)
    email = doctor_email or f"{username}@medicare.com"
    if query("SELECT id FROM users WHERE email=?",(email,),one=True):
        email = f"{username}{doctor_id}@medicare.com"
    uid = execute("INSERT OR IGNORE INTO users (username,email,password,plain_password,role,full_name,doctor_id) VALUES (?,?,?,?,?,?,?)",
        (username, email, hash_pw(password), password, 'doctor', doctor_name, doctor_id))
    return {'username': username, 'password': password, 'email': email}

def create_tables():
    with get_db() as conn:
        conn.executescript(SCHEMA)
        conn.commit()
    # Migrations for existing databases — add columns if missing
    try:
        cols = [r['name'] for r in query("PRAGMA table_info(appointments)")]
        if 'amount' not in cols:
            execute("ALTER TABLE appointments ADD COLUMN amount REAL DEFAULT 0")
            print("✅ Migration: added 'amount' column to appointments")
    except Exception as e:
        print(f"Migration note: {e}")
    try:
        ucols = [r['name'] for r in query("PRAGMA table_info(users)")]
        if 'doctor_id' not in ucols:
            execute("ALTER TABLE users ADD COLUMN doctor_id INTEGER REFERENCES doctors(id)")
            print("✅ Migration: added 'doctor_id' column to users")
        if 'plain_password' not in ucols:
            execute("ALTER TABLE users ADD COLUMN plain_password TEXT")
            print("✅ Migration: added 'plain_password' column to users")
    except Exception as e:
        print(f"Migration note: {e}")

def seed_database():
    if query("SELECT COUNT(*) as c FROM doctors", one=True)['c'] > 0:
        # Still seed service tables if they were added later and are empty
        if query("SELECT COUNT(*) as c FROM lab_tests", one=True)['c'] == 0:
            for name,cat,desc,price,turnaround in LAB_TESTS_SEED:
                execute("INSERT INTO lab_tests (name,category,description,price,turnaround) VALUES (?,?,?,?,?)",(name,cat,desc,price,turnaround))
        if query("SELECT COUNT(*) as c FROM medicines", one=True)['c'] == 0:
            for name,cat,desc,price,stock,reorder,supplier,expiry in MEDICINES_SEED:
                execute("INSERT INTO medicines (name,category,description,unit_price,stock_qty,reorder_level,supplier,expiry_date) VALUES (?,?,?,?,?,?,?,?)",(name,cat,desc,price,stock,reorder,supplier,expiry))
        if query("SELECT COUNT(*) as c FROM radiology_services", one=True)['c'] == 0:
            for name,modality,desc,price,prep,duration in RADIOLOGY_SEED:
                execute("INSERT INTO radiology_services (name,modality,description,price,preparation,duration_minutes) VALUES (?,?,?,?,?,?)",(name,modality,desc,price,prep,duration))
        return
    print("Seeding database...")
    # Admin credentials from env vars — never hard-coded
    admin_user  = os.environ.get('ADMIN_USERNAME', 'admin')
    admin_email = os.environ.get('ADMIN_EMAIL',    'admin@medicare.com')
    admin_pw    = os.environ.get('ADMIN_PASSWORD',  'admin123')
    for uname,email,pw,role,fname in [
        (admin_user, admin_email, admin_pw, "admin", "System Admin"),
        ("doctor1","doctor@medicare.com","doctor123","doctor","Dr. House"),
        ("staff1","staff@medicare.com","staff123","staff","Nurse Joy"),
    ]:
        execute("INSERT OR IGNORE INTO users (username,email,password,plain_password,role,full_name) VALUES (?,?,?,?,?,?)",
                (uname,email,hash_pw(pw),pw,role,fname))
    for slug,name,desc in DEPARTMENTS_SEED:
        execute("INSERT OR IGNORE INTO departments (slug,name,description) VALUES (?,?,?)",(slug,name,desc))
    for name,spec,dept,exp,qual in DOCTORS_SEED:
        did = execute("INSERT INTO doctors (name,specialization,department,experience,qualification) VALUES (?,?,?,?,?)",(name,spec,dept,exp,qual))
        create_doctor_user(did, name)
    for fn,ln,dob,gender,bg,contact,email in PATIENTS_SEED:
        execute("INSERT INTO patients (first_name,last_name,date_of_birth,gender,blood_group,contact,email) VALUES (?,?,?,?,?,?,?)",(fn,ln,dob,gender,bg,contact,email))
    today = date.today().strftime('%Y-%m-%d')
    for pid,did,tm,reason,status in [(1,1,"10:00","Chest pain follow-up","Confirmed"),(2,4,"11:30","Headache evaluation","Pending"),(3,7,"14:00","Knee injury","Completed"),(4,10,"15:30","Annual check-up","Confirmed"),(5,1,"16:00","ECG review","Pending")]:
        execute("INSERT INTO appointments (patient_id,doctor_id,appointment_date,appointment_time,reason,status) VALUES (?,?,?,?,?,?)",(pid,did,today,tm,reason,status))
    # Seed lab tests
    for name,cat,desc,price,turnaround in LAB_TESTS_SEED:
        execute("INSERT INTO lab_tests (name,category,description,price,turnaround) VALUES (?,?,?,?,?)",(name,cat,desc,price,turnaround))
    # Seed medicines
    for name,cat,desc,price,stock,reorder,supplier,expiry in MEDICINES_SEED:
        execute("INSERT INTO medicines (name,category,description,unit_price,stock_qty,reorder_level,supplier,expiry_date) VALUES (?,?,?,?,?,?,?,?)",(name,cat,desc,price,stock,reorder,supplier,expiry))
    # Seed radiology services
    for name,modality,desc,price,prep,duration in RADIOLOGY_SEED:
        execute("INSERT INTO radiology_services (name,modality,description,price,preparation,duration_minutes) VALUES (?,?,?,?,?,?)",(name,modality,desc,price,prep,duration))
    print("Seeding complete.")

# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    d = request.json or {}
    u = d.get('username','').strip()
    p = d.get('password','').strip()
    if not u or not p:
        return jsonify({'error':'Username and password required'}), 400
    import time; time.sleep(0.4)   # slow brute-force attempts
    user = query("SELECT * FROM users WHERE (username=? OR email=?) AND password=?",(u,u,hash_pw(p)),one=True)
    if not user:
        return jsonify({'error':'Invalid username or password'}), 401
    doctor_id = user.get('doctor_id') if 'doctor_id' in user else None
    session['user_id']   = user['id']
    session['username']  = user['username']
    session['role']      = user['role']
    session['full_name'] = user['full_name'] or user['username']
    session['doctor_id'] = doctor_id
    session.permanent    = True
    return jsonify({'message':'Login successful','user':{'id':user['id'],'username':user['username'],'role':user['role'],'full_name':user['full_name'],'doctor_id':doctor_id}})

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'message':'Logged out'})

@app.route('/api/auth/me')
def api_me():
    if not logged_in():
        return jsonify({'logged_in':False})
    return jsonify({'logged_in':True,'user':{'id':session['user_id'],'username':session['username'],'role':session['role'],'full_name':session['full_name'],'doctor_id':session.get('doctor_id')}})

# ── User management ───────────────────────────────────────────────────────────

@app.route('/api/users', methods=['GET','POST'])
def api_users():
    err = require_login()
    if err: return err
    if session.get('role') != 'admin':
        return jsonify({'error':'Admin only'}), 403
    if request.method == 'POST':
        d = request.json or {}
        if not d.get('username') or not d.get('password') or not d.get('email'):
            return jsonify({'error':'Username, email and password required'}), 400
        existing = query("SELECT id FROM users WHERE username=? OR email=?",(d['username'],d['email']),one=True)
        if existing:
            return jsonify({'error':'Username or email already exists'}), 409
        plain = d['password']
        nid = execute("INSERT INTO users (username,email,password,plain_password,role,full_name,doctor_id) VALUES (?,?,?,?,?,?,?)",
            (d['username'],d['email'],hash_pw(plain),plain,d.get('role','staff'),d.get('full_name',''),d.get('doctor_id')))
        return jsonify({'message':'User created','id':nid}), 201
    return jsonify(query("SELECT id,username,email,role,full_name,plain_password,created_at FROM users ORDER BY id"))

@app.route('/api/users/<int:uid>', methods=['PUT','DELETE'])
def api_user(uid):
    err = require_login()
    if err: return err
    if session.get('role') != 'admin':
        return jsonify({'error':'Admin only'}), 403
    row = query("SELECT * FROM users WHERE id=?",(uid,),one=True)
    if not row: return jsonify({'error':'Not found'}), 404
    if request.method == 'DELETE':
        if uid == session['user_id']:
            return jsonify({'error':'Cannot delete yourself'}), 400
        execute("DELETE FROM users WHERE id=?",(uid,))
        return jsonify({'message':'User deleted'})
    d = request.json or {}
    new_pw = hash_pw(d['password']) if d.get('password') else row['password']
    execute("UPDATE users SET username=?,email=?,role=?,full_name=?,password=?,doctor_id=? WHERE id=?",
        (d.get('username',row['username']),d.get('email',row['email']),
         d.get('role',row['role']),d.get('full_name',row['full_name']),new_pw,
         d.get('doctor_id',row.get('doctor_id')),uid))
    return jsonify({'message':'User updated'})

# ── Core API ──────────────────────────────────────────────────────────────────

@app.route('/api/departments', methods=['GET','POST'])
def api_departments():
    if request.method == 'POST':
        err = require_login()
        if err: return err
        if session.get('role') != 'admin':
            return jsonify({'error':'Admin only'}), 403
        d = request.json or {}
        name = d.get('name','').strip()
        slug = d.get('slug','').strip() or name.lower().replace(' ','_')
        icon = d.get('icon','🏥').strip()
        desc = d.get('description','').strip()
        if not name:
            return jsonify({'error':'Name is required'}), 400
        existing = query("SELECT id FROM departments WHERE slug=? OR name=?",(slug,name),one=True)
        if existing:
            return jsonify({'error':'Department already exists'}), 409
        nid = execute("INSERT INTO departments (slug,name,icon,description) VALUES (?,?,?,?)",(slug,name,icon,desc))
        return jsonify({'message':'Department added','id':nid,'slug':slug,'name':name,'icon':icon,'description':desc}), 201
    is_admin = logged_in() and session.get('role') == 'admin'
    if is_admin:
        return jsonify(query("SELECT id,slug,name,icon,description,hidden FROM departments ORDER BY name"))
    return jsonify(query("SELECT id,slug,name,icon,description,hidden FROM departments WHERE hidden=0 ORDER BY name"))

@app.route('/api/departments/<int:did>/toggle-hidden', methods=['POST'])
def api_department_toggle_hidden(did):
    err = require_login()
    if err: return err
    if session.get('role') != 'admin':
        return jsonify({'error':'Admin only'}), 403
    row = query("SELECT * FROM departments WHERE id=?", (did,), one=True)
    if not row: return jsonify({'error':'Not found'}), 404
    new_hidden = 0 if row['hidden'] else 1
    execute("UPDATE departments SET hidden=? WHERE id=?", (new_hidden, did))
    # Also hide/show all doctors in this department
    new_available = 0 if new_hidden else 1
    execute("UPDATE doctors SET available=? WHERE department=?", (new_available, row['name']))
    affected = query("SELECT COUNT(*) as c FROM doctors WHERE department=?", (row['name'],), one=True)['c']
    return jsonify({
        'message': f'Department {"hidden" if new_hidden else "visible"} — {affected} doctor(s) {"hidden" if new_hidden else "shown"}',
        'hidden': new_hidden,
        'doctors_affected': affected
    })

@app.route('/api/departments/<int:did>', methods=['PUT','DELETE'])
def api_department(did):
    err = require_login()
    if err: return err
    if session.get('role') != 'admin':
        return jsonify({'error':'Admin only'}), 403
    row = query("SELECT * FROM departments WHERE id=?", (did,), one=True)
    if not row: return jsonify({'error':'Not found'}), 404
    if request.method == 'PUT':
        d = request.json or {}
        name = d.get('name', row['name']).strip()
        icon = d.get('icon', row['icon'] or '🏥').strip()
        desc = d.get('description', row['description'] or '').strip()
        slug = d.get('slug', row['slug']).strip()
        execute("UPDATE departments SET name=?,icon=?,description=?,slug=? WHERE id=?", (name,icon,desc,slug,did))
        return jsonify({'message':'Department updated'})
    # DELETE — check if any doctors are in this department
    doctors_in_dept = query("SELECT COUNT(*) as c FROM doctors WHERE department=?", (row['name'],), one=True)['c']
    if doctors_in_dept > 0:
        return jsonify({'error': f'Cannot delete — {doctors_in_dept} doctor(s) are assigned to this department. Reassign them first.'}), 400
    execute("DELETE FROM departments WHERE id=?", (did,))
    return jsonify({'message':'Department deleted'})


@app.route('/api/doctors', methods=['GET','POST'])
def api_doctors():
    if request.method == 'POST':
        err = require_login()
        if err: return err
        d = request.json or {}
        nid = execute("INSERT INTO doctors (name,specialization,department,experience,contact,email,qualification) VALUES (?,?,?,?,?,?,?)",
            (d.get('name',''),d.get('specialization',''),d.get('department',''),d.get('experience',0),d.get('contact'),d.get('email'),d.get('qualification')))
        # Auto-create a login account for the doctor
        creds = create_doctor_user(nid, d.get('name',''), d.get('email'))
        resp = {'message':'Doctor added','id':nid}
        if creds:
            resp['login_credentials'] = creds
        return jsonify(resp), 201
    dept = request.args.get('department','')
    # Non-admins (including public/patients) only see available doctors in visible departments
    is_admin = logged_in() and session.get('role') == 'admin'
    avail_filter = '' if is_admin else ' AND d.available=1'
    hidden_filter = '' if is_admin else ' AND (dep.hidden IS NULL OR dep.hidden=0)'
    if dept:
        return jsonify(query(f"SELECT d.* FROM doctors d LEFT JOIN departments dep ON dep.name=d.department WHERE d.department=?{avail_filter}{hidden_filter} ORDER BY d.name",(dept,)))
    return jsonify(query(f"SELECT d.* FROM doctors d LEFT JOIN departments dep ON dep.name=d.department WHERE 1=1{avail_filter}{hidden_filter} ORDER BY d.department,d.name"))

@app.route('/api/admin/reset-db', methods=['POST'])
def api_reset_db():
    """Wipe doctors/users and reseed cleanly. Admin only."""
    err = require_login()
    if err: return err
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    try:
        print("🔄 DB Reset triggered by admin...")
        # Order matters — delete child tables first
        execute("DELETE FROM appointments")
        execute("DELETE FROM patients")
        execute("DELETE FROM users WHERE role='doctor'")
        execute("DELETE FROM users WHERE username IN ('doctor1','staff1')")
        execute("DELETE FROM doctors")
        # Reset sequences safely
        for tbl in ['doctors','users','appointments','patients']:
            try: execute(f"UPDATE sqlite_sequence SET seq=0 WHERE name='{tbl}'")
            except: pass
        # Ensure admin exists
        admin_user  = os.environ.get('ADMIN_USERNAME', 'admin')
        admin_email = os.environ.get('ADMIN_EMAIL',    'admin@medicare.com')
        admin_pw    = os.environ.get('ADMIN_PASSWORD',  'admin123')
        execute("INSERT OR IGNORE INTO users (username,email,password,plain_password,role,full_name) VALUES (?,?,?,?,?,?)",
            (admin_user, admin_email, hash_pw(admin_pw), admin_pw, 'admin', 'System Admin'))
        # Reseed all 37 doctors
        doctor_creds = []
        for name, spec, dept, exp, qual in DOCTORS_SEED:
            did = execute("INSERT INTO doctors (name,specialization,department,experience,qualification) VALUES (?,?,?,?,?)",
                (name, spec, dept, exp, qual))
            creds = create_doctor_user(did, name)
            if creds:
                doctor_creds.append({'id': did, 'name': name, 'username': creds['username'], 'password': creds['password']})
                print(f"  ✅ {name} → {creds['username']} / {creds['password']}")
        # Reseed sample patients
        for fn,ln,dob,gender,bg,contact,email in PATIENTS_SEED:
            execute("INSERT INTO patients (first_name,last_name,date_of_birth,gender,blood_group,contact,email) VALUES (?,?,?,?,?,?,?)",
                (fn,ln,dob,gender,bg,contact,email))
        print(f"✅ Reset complete. {len(doctor_creds)} doctors reseeded.")
        return jsonify({'message': f'Reset complete! {len(doctor_creds)} doctors reseeded.', 'doctors': doctor_creds})
    except Exception as e:
        print(f"❌ Reset error: {e}")
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/doctors/credentials')
def api_doctor_credentials():
    err = require_login()
    if err: return err
    if session.get('role') != 'admin':
        return jsonify({'error':'Admin only'}), 403
    rows = query("""SELECT u.username, u.email, u.role, u.full_name, u.doctor_id,
                    d.specialization, d.department
                    FROM users u JOIN doctors d ON d.id=u.doctor_id
                    WHERE u.role='doctor' ORDER BY u.full_name""")
    return jsonify(rows)

@app.route('/api/doctors/<int:did>/reset-password', methods=['POST'])
def api_doctor_reset_password(did):
    err = require_login()
    if err: return err
    if session.get('role') != 'admin':
        return jsonify({'error':'Admin only'}), 403
    doc = query("SELECT * FROM doctors WHERE id=?",(did,),one=True)
    if not doc: return jsonify({'error':'Not found'}), 404
    user = query("SELECT * FROM users WHERE doctor_id=?",(did,),one=True)
    if not user: return jsonify({'error':'No login account found for this doctor'}), 404
    _, password = generate_doctor_credentials(doc['name'], did)
    execute("UPDATE users SET password=?,plain_password=? WHERE doctor_id=?",(hash_pw(password),password,did))
    return jsonify({'message':'Password reset','username':user['username'],'new_password':password})

@app.route('/api/doctors/<int:did>/availability', methods=['PUT'])
def api_doctor_availability(did):
    err = require_login()
    if err: return err
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    row = query("SELECT * FROM doctors WHERE id=?", (did,), one=True)
    if not row: return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    avail = 1 if d.get('available') else 0
    execute("UPDATE doctors SET available=? WHERE id=?", (avail, did))
    return jsonify({'message': 'Doctor visibility updated', 'available': avail})

@app.route('/api/doctors/<int:did>/update-user', methods=['POST'])
def api_doctor_update_user(did):
    """Update the auto-created doctor user account with admin-chosen credentials."""
    err = require_login()
    if err: return err
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    doc = query("SELECT * FROM doctors WHERE id=?", (did,), one=True)
    if not doc: return jsonify({'error': 'Doctor not found'}), 404
    user = query("SELECT * FROM users WHERE doctor_id=?", (did,), one=True)
    if not user: return jsonify({'error': 'No user account found for this doctor'}), 404
    d = request.json or {}
    new_username = d.get('username', '').strip()
    new_email    = d.get('email', '').strip()
    new_password = d.get('password', '').strip()
    new_fullname = d.get('full_name', doc['name']).strip()
    if not new_username or not new_email or not new_password:
        return jsonify({'error': 'username, email and password required'}), 400
    conflict = query("SELECT id FROM users WHERE (username=? OR email=?) AND id!=?", (new_username, new_email, user['id']), one=True)
    if conflict: return jsonify({'error': 'Username or email already taken'}), 409
    execute("UPDATE users SET username=?, email=?, password=?, full_name=? WHERE id=?",
        (new_username, new_email, hash_pw(new_password), new_fullname, user['id']))
    return jsonify({'message': 'Doctor user account updated', 'username': new_username})

@app.route('/api/doctors/<int:did>', methods=['GET','PUT','DELETE'])
def api_doctor(did):
    row = query("SELECT * FROM doctors WHERE id=?", (did,), one=True)
    if not row: return jsonify({'error':'Not found'}), 404
    if request.method == 'GET': return jsonify(row)
    err = require_login()
    if err: return err
    if request.method == 'PUT':
        d = request.json or {}
        execute("UPDATE doctors SET name=?,specialization=?,department=?,experience=?,contact=?,email=?,qualification=? WHERE id=?",
            (d.get('name',row['name']),d.get('specialization',row['specialization']),
             d.get('department',row['department']),d.get('experience',row['experience']),
             d.get('contact',row['contact']),d.get('email',row['email']),
             d.get('qualification',row['qualification']),did))
        return jsonify({'message':'Doctor updated'})
    # DELETE — remove linked user account first to avoid foreign key conflict
    # Check if doctor has any appointments first
    appt_count = query("SELECT COUNT(*) as c FROM appointments WHERE doctor_id=?", (did,), one=True)['c']
    if appt_count > 0:
        return jsonify({'error': f'Cannot delete — {appt_count} appointment(s) exist for this doctor. Please reassign or cancel them first.', 'appointment_count': appt_count}), 400
    try:
        execute("DELETE FROM users WHERE doctor_id=?", (did,))
    except Exception:
        pass
    execute("DELETE FROM doctors WHERE id=?", (did,))
    return jsonify({'message':'Doctor deleted'})

@app.route('/api/doctors/<int:did>/create-login', methods=['POST'])
def api_doctor_create_login(did):
    """Create a login for an existing doctor who has no user account yet."""
    err = require_login()
    if err: return err
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    doc = query("SELECT * FROM doctors WHERE id=?", (did,), one=True)
    if not doc: return jsonify({'error': 'Doctor not found'}), 404
    # Check if already has a login
    existing = query("SELECT id, username FROM users WHERE doctor_id=?", (did,), one=True)
    if existing:
        return jsonify({'error': f'Doctor already has a login: {existing["username"]}'}), 409
    d = request.json or {}
    # Use provided credentials or auto-generate
    if d.get('username') and d.get('password'):
        username = d['username'].strip()
        password = d['password'].strip()
        email = d.get('email', '').strip() or f"{username}@medicare.com"
        # Check uniqueness
        conflict = query("SELECT id FROM users WHERE username=? OR email=?", (username, email), one=True)
        if conflict: return jsonify({'error': 'Username or email already taken'}), 409
        execute("INSERT INTO users (username,email,password,plain_password,role,full_name,doctor_id) VALUES (?,?,?,?,?,?,?)",
            (username, email, hash_pw(password), password, 'doctor', doc['name'], did))
    else:
        # Auto-generate
        creds = create_doctor_user(did, doc['name'], doc.get('email'))
        if not creds:
            return jsonify({'error': 'Login already exists for this doctor'}), 409
        username = creds['username']
        password = creds['password']
        email    = creds['email']
    return jsonify({'message': 'Login created', 'username': username, 'password': password, 'email': email}), 201

@app.route('/api/patients', methods=['GET','POST'])
def api_patients():
    if request.method == 'POST':
        # Public patients endpoint — allow unauthenticated patient creation for appointment booking
        # (admin-only operations like DELETE are still protected)
        d = request.json or {}
        nid = execute("INSERT INTO patients (first_name,last_name,date_of_birth,gender,blood_group,contact,email,address,emergency_contact) VALUES (?,?,?,?,?,?,?,?,?)",
            (d.get('first_name',''),d.get('last_name',''),d.get('date_of_birth','1990-01-01'),
             d.get('gender','Other'),d.get('blood_group'),d.get('contact',''),
             d.get('email'),d.get('address'),d.get('emergency_contact')))
        return jsonify({'message':'Patient added','id':nid}), 201
    s = request.args.get('search','')
    # If logged in as a doctor, only show patients with appointments for that doctor
    if logged_in() and session.get('role') == 'doctor' and session.get('doctor_id'):
        did = session['doctor_id']
        if s:
            return jsonify(query(
                """SELECT DISTINCT p.* FROM patients p
                   JOIN appointments a ON a.patient_id=p.id
                   WHERE a.doctor_id=? AND ((p.first_name||' '||p.last_name) LIKE ? OR p.contact LIKE ?)
                   ORDER BY p.id DESC""",
                (did, f'%{s}%', f'%{s}%')
            ))
        return jsonify(query(
            """SELECT DISTINCT p.* FROM patients p
               JOIN appointments a ON a.patient_id=p.id
               WHERE a.doctor_id=? ORDER BY p.id DESC""",
            (did,)
        ))
    if s:
        return jsonify(query("SELECT * FROM patients WHERE (first_name||' '||last_name) LIKE ? OR contact LIKE ? ORDER BY id DESC",(f'%{s}%',f'%{s}%')))
    return jsonify(query("SELECT * FROM patients ORDER BY id DESC"))

@app.route('/api/patients/<int:pid>', methods=['GET','PUT','DELETE'])
def api_patient(pid):
    row = query("SELECT * FROM patients WHERE id=?",(pid,),one=True)
    if not row: return jsonify({'error':'Not found'}),404
    if request.method == 'GET': return jsonify(row)
    err = require_login()
    if err: return err
    if request.method == 'PUT':
        d = request.json or {}
        execute("UPDATE patients SET first_name=?,last_name=?,gender=?,blood_group=?,contact=?,email=?,address=?,emergency_contact=? WHERE id=?",
            (d.get('first_name',row['first_name']),d.get('last_name',row['last_name']),
             d.get('gender',row['gender']),d.get('blood_group',row['blood_group']),
             d.get('contact',row['contact']),d.get('email',row['email']),
             d.get('address',row['address']),d.get('emergency_contact',row['emergency_contact']),pid))
        return jsonify({'message':'Patient updated'})
    execute("DELETE FROM patients WHERE id=?",(pid,))
    return jsonify({'message':'Patient deleted'})

@app.route('/api/appointments', methods=['GET','POST'])
def api_appointments():
    if request.method == 'POST':
        # Public booking — no login required for patients to book
        d = request.json or {}
        nid = execute("INSERT INTO appointments (patient_id,doctor_id,appointment_date,appointment_time,reason,status) VALUES (?,?,?,?,?,?)",
            (d['patient_id'],d['doctor_id'],d.get('appointment_date'),
             d.get('appointment_time','09:00'),d.get('reason','General Consultation'),'Pending'))
        return jsonify({'message':'Appointment booked','id':nid}), 201

    sf = request.args.get('status','')
    sql = """SELECT a.*, p.first_name||' '||p.last_name AS patient_name,
             p.email AS patient_email,
             d.name AS doctor_name, d.department
             FROM appointments a
             JOIN patients p ON p.id=a.patient_id
             JOIN doctors  d ON d.id=a.doctor_id"""
    # If logged in as a doctor, restrict to their own appointments
    doctor_filter = None
    if logged_in() and session.get('role') == 'doctor' and session.get('doctor_id'):
        doctor_filter = session['doctor_id']

    if doctor_filter:
        where = " WHERE a.doctor_id=?"
        if sf:
            where += " AND a.status=?"
            return jsonify(query(sql+where+" ORDER BY a.id DESC",(doctor_filter,sf)))
        return jsonify(query(sql+where+" ORDER BY a.id DESC",(doctor_filter,)))
    if sf:
        return jsonify(query(sql+" WHERE a.status=? ORDER BY a.id DESC",(sf,)))
    return jsonify(query(sql+" ORDER BY a.id DESC"))

@app.route('/api/appointments/<int:aid>/reschedule', methods=['POST'])
def api_appointment_reschedule(aid):
    err = require_login()
    if err: return err
    row = query("SELECT * FROM appointments WHERE id=?", (aid,), one=True)
    if not row: return jsonify({'error':'Not found'}), 404
    d = request.json or {}
    new_date = d.get('appointment_date', row['appointment_date'])
    new_time = d.get('appointment_time')
    if not new_time:
        return jsonify({'error': 'appointment_time is required'}), 400
    # Check if new slot is already confirmed by someone else
    conflict = query(
        "SELECT id FROM appointments WHERE doctor_id=? AND appointment_date=? AND appointment_time=? AND status='Confirmed' AND id!=?",
        (row['doctor_id'], new_date, new_time, aid), one=True
    )
    if conflict:
        return jsonify({'error': 'This slot is already confirmed for another patient. Please choose a different slot.'}), 409
    execute("UPDATE appointments SET appointment_date=?, appointment_time=?, status='Pending' WHERE id=?",
            (new_date, new_time, aid))
    # Send email notification if patient has email
    full = query("""SELECT a.*, p.first_name||' '||p.last_name AS patient_name,
                    p.email AS patient_email, d.name AS doctor_name, d.department
                    FROM appointments a JOIN patients p ON p.id=a.patient_id
                    JOIN doctors d ON d.id=a.doctor_id WHERE a.id=?""", (aid,), one=True)
    if full and full.get('patient_email'):
        html = build_status_change_email(
            full['patient_name'], full['doctor_name'], full['department'],
            new_date, new_time, 'Pending', aid)
        send_email_async(full['patient_email'],
            f"📅 Appointment Rescheduled — {HOSPITAL_NAME}", html)
    return jsonify({'message': 'Appointment rescheduled', 'new_date': new_date, 'new_time': new_time})


@app.route('/api/appointments/available-slots')
def api_available_slots():
    """Return time slots for a doctor on a given date, excluding confirmed ones."""
    doctor_id = request.args.get('doctor_id', type=int)
    date_str  = request.args.get('date', '')
    if not doctor_id or not date_str:
        return jsonify({'error': 'doctor_id and date required'}), 400

    # All 30-min slots from 09:00 to 17:30
    all_slots = []
    for h in range(9, 18):
        for m in (0, 30):
            if h == 17 and m == 30: break
            all_slots.append(f"{h:02d}:{m:02d}")

    # Slots already confirmed for this doctor on this date
    booked = query(
        "SELECT appointment_time FROM appointments WHERE doctor_id=? AND appointment_date=? AND status='Confirmed'",
        (doctor_id, date_str)
    )
    booked_times = {r['appointment_time'] for r in booked}

    slots = [{'time': s, 'available': s not in booked_times} for s in all_slots]
    return jsonify(slots)

@app.route('/api/appointments/<int:aid>', methods=['GET','PUT','DELETE'])
def api_appointment(aid):
    row = query("SELECT * FROM appointments WHERE id=?",(aid,),one=True)
    if not row: return jsonify({'error':'Not found'}),404
    if request.method == 'GET':
        # Always return joined patient/doctor info so patient_email is never missing
        full = query("""SELECT a.*, p.first_name||' '||p.last_name AS patient_name,
                        p.email AS patient_email, p.contact AS patient_contact,
                        d.name AS doctor_name, d.department, d.specialization
                        FROM appointments a
                        JOIN patients p ON p.id=a.patient_id
                        JOIN doctors  d ON d.id=a.doctor_id
                        WHERE a.id=?""",(aid,),one=True)
        return jsonify(full if full else row)
    err = require_login()
    if err: return err
    if request.method == 'PUT':
        d = request.json or {}
        old_status = row['status']
        new_status = d.get('status', old_status)
        new_reason = d.get('reason', row['reason'])
        new_amount = d.get('amount', row.get('amount', 0))
        execute("UPDATE appointments SET status=?,reason=?,amount=? WHERE id=?",(new_status,new_reason,new_amount,aid))

        # Send confirmation email ONLY when status changes TO Confirmed
        if new_status == 'Confirmed' and old_status != 'Confirmed':
            full = query("""SELECT a.*, p.first_name||' '||p.last_name AS patient_name,
                            p.email AS patient_email, d.name AS doctor_name, d.department
                            FROM appointments a JOIN patients p ON p.id=a.patient_id
                            JOIN doctors d ON d.id=a.doctor_id WHERE a.id=?""",(aid,),one=True)
            if full and full.get('patient_email'):
                html = build_confirmation_email(
                    full['patient_name'], full['doctor_name'], full['department'],
                    full['appointment_date'], full['appointment_time'],
                    new_reason, aid)
                send_email_async(full['patient_email'],
                    f"✅ Appointment Confirmed — {HOSPITAL_NAME}", html)
                print(f"📧 Confirmation email sent to {full['patient_email']}")
        elif new_status in ('Completed', 'Cancelled', 'No-Show') and new_status != old_status:
            full = query("""SELECT a.*, p.first_name||' '||p.last_name AS patient_name,
                            p.email AS patient_email, d.name AS doctor_name, d.department
                            FROM appointments a JOIN patients p ON p.id=a.patient_id
                            JOIN doctors d ON d.id=a.doctor_id WHERE a.id=?""",(aid,),one=True)
            if full and full.get('patient_email'):
                html = build_status_change_email(
                    full['patient_name'], full['doctor_name'], full['department'],
                    full['appointment_date'], full['appointment_time'], new_status, aid)
                send_email_async(full['patient_email'],
                    f"📋 Appointment {new_status} — {HOSPITAL_NAME}", html)

        return jsonify({'message':'Appointment updated', 'old_status': old_status, 'new_status': new_status})
    execute("DELETE FROM appointments WHERE id=?",(aid,))
    return jsonify({'message':'Appointment deleted'})

@app.route('/api/dashboard/stats')
def api_stats():
    today = date.today().strftime('%Y-%m-%d')
    if logged_in() and session.get('role') == 'doctor' and session.get('doctor_id'):
        did = session['doctor_id']
        return jsonify({
            'total_patients':     query("SELECT COUNT(DISTINCT patient_id) as c FROM appointments WHERE doctor_id=?",(did,),one=True)['c'],
            'total_doctors':      query("SELECT COUNT(*) as c FROM doctors",one=True)['c'],
            'today_appointments': query("SELECT COUNT(*) as c FROM appointments WHERE appointment_date=? AND doctor_id=?",(today,did),one=True)['c'],
            'pending':            query("SELECT COUNT(*) as c FROM appointments WHERE status='Pending' AND doctor_id=?",(did,),one=True)['c'],
            'confirmed':          query("SELECT COUNT(*) as c FROM appointments WHERE status='Confirmed' AND doctor_id=?",(did,),one=True)['c'],
            'completed':          query("SELECT COUNT(*) as c FROM appointments WHERE status='Completed' AND doctor_id=?",(did,),one=True)['c'],
            'cancelled':          query("SELECT COUNT(*) as c FROM appointments WHERE status='Cancelled' AND doctor_id=?",(did,),one=True)['c'],
            'no_show':            query("SELECT COUNT(*) as c FROM appointments WHERE status='No-Show' AND doctor_id=?",(did,),one=True)['c'],
            'total_appointments': query("SELECT COUNT(*) as c FROM appointments WHERE doctor_id=?",(did,),one=True)['c'],
            'total_departments':  query("SELECT COUNT(*) as c FROM departments",one=True)['c'],
        })
    return jsonify({
        'total_patients':     query("SELECT COUNT(*) as c FROM patients",one=True)['c'],
        'total_doctors':      query("SELECT COUNT(*) as c FROM doctors",one=True)['c'],
        'today_appointments': query("SELECT COUNT(*) as c FROM appointments WHERE appointment_date=?",(today,),one=True)['c'],
        'pending':            query("SELECT COUNT(*) as c FROM appointments WHERE status='Pending'",one=True)['c'],
        'confirmed':          query("SELECT COUNT(*) as c FROM appointments WHERE status='Confirmed'",one=True)['c'],
        'completed':          query("SELECT COUNT(*) as c FROM appointments WHERE status='Completed'",one=True)['c'],
        'cancelled':          query("SELECT COUNT(*) as c FROM appointments WHERE status='Cancelled'",one=True)['c'],
        'no_show':            query("SELECT COUNT(*) as c FROM appointments WHERE status='No-Show'",one=True)['c'],
        'total_appointments': query("SELECT COUNT(*) as c FROM appointments",one=True)['c'],
        'total_departments':  query("SELECT COUNT(*) as c FROM departments",one=True)['c'],
    })

# ── Emergency Services ────────────────────────────────────────────────────────

EMERGENCY_CONFIG_FILE = os.path.join(os.path.dirname(DB_PATH), 'emergency_config.json')

def load_emergency_config():
    defaults = {
        'phone': HOSPITAL_PHONE,
        'response_time': '8 min',
        'total_ambulances': 24,
        'available_ambulances': 18,
        'on_duty': 6,
        'services': [
            {'icon': '🚑', 'name': 'Emergency Ambulance', 'desc': '24/7 rapid dispatch with trained paramedics'},
            {'icon': '🏥', 'name': 'Emergency Trauma Care', 'desc': 'Immediate trauma assessment and stabilization'},
            {'icon': '❤️', 'name': 'Cardiac Emergency', 'desc': 'Rapid response for cardiac events & CPR'},
            {'icon': '🧠', 'name': 'Neuro Emergency', 'desc': 'Stroke and brain emergency fast-track protocol'},
            {'icon': '🔥', 'name': 'Burns & Accidents', 'desc': 'Specialized burn and accident emergency care'},
            {'icon': '👶', 'name': 'Pediatric Emergency', 'desc': 'Child emergency care with pediatric specialists'},
        ]
    }
    try:
        if os.path.exists(EMERGENCY_CONFIG_FILE):
            import json
            with open(EMERGENCY_CONFIG_FILE) as f:
                saved = json.load(f)
                defaults.update(saved)
    except:
        pass
    return defaults

@app.route('/api/emergency/config', methods=['GET', 'POST'])
def api_emergency_config():
    if request.method == 'GET':
        return jsonify(load_emergency_config())
    err = require_login()
    if err: return err
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    import json
    d = request.json or {}
    cfg = load_emergency_config()
    cfg.update({k: v for k, v in d.items() if k in cfg})
    with open(EMERGENCY_CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)
    return jsonify({'message': 'Emergency config saved'})

# ── Admissions ────────────────────────────────────────────────────────────────

@app.route('/api/admissions', methods=['GET','POST'])
def api_admissions():
    err = require_login()
    if err: return err
    if request.method == 'POST':
        d = request.json or {}
        if not d.get('patient_id') or not d.get('ward') or not d.get('admit_date'):
            return jsonify({'error': 'patient_id, ward and admit_date are required'}), 400
        nid = execute("""INSERT INTO admissions
            (patient_id,doctor_id,ward,room_no,bed_no,admit_date,discharge_date,
             diagnosis,treatment,amount,status,notes,admitted_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (d['patient_id'], d.get('doctor_id'), d['ward'],
             d.get('room_no',''), d.get('bed_no',''), d['admit_date'],
             d.get('discharge_date'), d.get('diagnosis',''), d.get('treatment',''),
             d.get('amount',0), d.get('status','Admitted'), d.get('notes',''),
             session.get('user_id')))
        return jsonify({'message':'Patient admitted','id':nid}), 201

    rows = query("""SELECT a.*, p.first_name||' '||p.last_name AS patient_name,
        p.contact AS patient_contact, p.blood_group,
        d.name AS doctor_name, d.department,
        u.full_name AS admitted_by_name
        FROM admissions a
        JOIN patients p ON p.id=a.patient_id
        LEFT JOIN doctors d ON d.id=a.doctor_id
        LEFT JOIN users u ON u.id=a.admitted_by
        ORDER BY a.id DESC""")
    return jsonify(rows)

@app.route('/api/admissions/<int:aid>', methods=['GET','PUT','DELETE'])
def api_admission(aid):
    err = require_login()
    if err: return err
    row = query("SELECT * FROM admissions WHERE id=?", (aid,), one=True)
    if not row: return jsonify({'error':'Not found'}), 404
    if request.method == 'GET': return jsonify(row)
    if request.method == 'DELETE':
        execute("DELETE FROM admissions WHERE id=?", (aid,))
        return jsonify({'message':'Admission record deleted'})
    d = request.json or {}
    execute("""UPDATE admissions SET ward=?,room_no=?,bed_no=?,admit_date=?,
        discharge_date=?,diagnosis=?,treatment=?,amount=?,status=?,notes=?,doctor_id=?
        WHERE id=?""",
        (d.get('ward', row['ward']),
         d.get('room_no', row['room_no']),
         d.get('bed_no', row['bed_no']),
         d.get('admit_date', row['admit_date']),
         d.get('discharge_date', row['discharge_date']),
         d.get('diagnosis', row['diagnosis']),
         d.get('treatment', row['treatment']),
         d.get('amount', row['amount']),
         d.get('status', row['status']),
         d.get('notes', row['notes']),
         d.get('doctor_id', row['doctor_id']),
         aid))
    return jsonify({'message':'Admission updated'})

@app.route('/api/patients/<int:pid>/admissions')
def api_patient_admissions(pid):
    err = require_login()
    if err: return err
    rows = query("""SELECT a.*, d.name AS doctor_name, u.full_name AS admitted_by_name
        FROM admissions a
        LEFT JOIN doctors d ON d.id=a.doctor_id
        LEFT JOIN users u ON u.id=a.admitted_by
        WHERE a.patient_id=? ORDER BY a.admit_date DESC""", (pid,))
    return jsonify(rows)

# ── Reports ───────────────────────────────────────────────────────────────────

@app.route('/api/reports/patients')
def report_patients():
    rows = query("""SELECT p.id, p.first_name||' '||p.last_name AS name,
        p.gender, p.blood_group, p.contact, p.email, p.date_of_birth, p.created_at,
        COUNT(a.id) AS total_appointments
        FROM patients p LEFT JOIN appointments a ON a.patient_id=p.id
        GROUP BY p.id ORDER BY p.created_at DESC""")
    total  = len(rows)
    male   = sum(1 for r in rows if r['gender']=='Male')
    female = sum(1 for r in rows if r['gender']=='Female')
    blood  = {}
    for r in rows:
        bg = r['blood_group'] or 'Unknown'
        blood[bg] = blood.get(bg,0)+1
    return jsonify({'patients':rows,'summary':{'total':total,'male':male,'female':female,'blood_groups':blood}})

@app.route('/api/reports/appointments')
def report_appointments():
    rows = query("""SELECT a.id, p.first_name||' '||p.last_name AS patient_name,
        d.name AS doctor_name, d.department, a.appointment_date, a.appointment_time,
        a.reason, a.status, a.created_at FROM appointments a
        JOIN patients p ON p.id=a.patient_id JOIN doctors d ON d.id=a.doctor_id
        ORDER BY a.appointment_date DESC, a.appointment_time DESC""")
    by_dept = {}
    for r in rows:
        d = r['department']
        by_dept[d] = by_dept.get(d,0)+1
    return jsonify({'appointments':rows,'summary':{
        'total':len(rows),
        'pending':  sum(1 for r in rows if r['status']=='Pending'),
        'confirmed':sum(1 for r in rows if r['status']=='Confirmed'),
        'completed':sum(1 for r in rows if r['status']=='Completed'),
        'cancelled':sum(1 for r in rows if r['status']=='Cancelled'),
        'no_show':  sum(1 for r in rows if r['status']=='No-Show'),
        'by_department':by_dept}})

@app.route('/api/reports/departments')
def report_departments():
    depts = query("SELECT name FROM departments ORDER BY name")
    result = []
    for dept in depts:
        name = dept['name']
        result.append({
            'department': name,
            'doctors':    query("SELECT COUNT(*) as c FROM doctors WHERE department=?",(name,),one=True)['c'],
            'total_appointments': query("SELECT COUNT(*) as c FROM appointments a JOIN doctors d ON d.id=a.doctor_id WHERE d.department=?",(name,),one=True)['c'],
            'completed':  query("SELECT COUNT(*) as c FROM appointments a JOIN doctors d ON d.id=a.doctor_id WHERE d.department=? AND a.status='Completed'",(name,),one=True)['c'],
        })
    return jsonify({'departments':result,'summary':{'total_departments':len(result),'total_doctors':query("SELECT COUNT(*) as c FROM doctors",one=True)['c']}})

@app.route('/api/reports/financial')
def report_financial():
    appt_rows = query("""SELECT a.id, p.first_name||' '||p.last_name AS patient_name,
        d.name AS doctor_name, d.department,
        a.appointment_date, a.status, COALESCE(a.amount, 0) AS amount FROM appointments a
        JOIN patients p ON p.id=a.patient_id JOIN doctors d ON d.id=a.doctor_id
        ORDER BY a.appointment_date DESC""")

    # Build unified billing records
    records = []
    for r in appt_rows:
        records.append({
            'id': f"APT-{r['id']}",
            'type': 'Consultation',
            'patient_name': r['patient_name'],
            'service_name': f"Consultation — {r['doctor_name']}",
            'department': r['department'],
            'date': r['appointment_date'],
            'status': r['status'],
            'amount': r['amount'] or 0,
        })

    # Lab bookings
    lab_rows = query("SELECT * FROM lab_bookings ORDER BY booking_date DESC")
    for r in lab_rows:
        records.append({
            'id': f"LAB-{r['id']}",
            'type': 'Laboratory',
            'patient_name': r['patient_name'],
            'service_name': r['test_name'],
            'department': 'Laboratory',
            'date': r['booking_date'],
            'status': r['status'],
            'amount': r['amount'],
            'note': ''
        })

    # Radiology bookings
    rad_rows = query("SELECT * FROM radiology_bookings ORDER BY booking_date DESC")
    for r in rad_rows:
        records.append({
            'id': f"RAD-{r['id']}",
            'type': 'Radiology',
            'patient_name': r['patient_name'],
            'service_name': r['service_name'],
            'department': 'Radiology',
            'date': r['booking_date'],
            'status': r['status'],
            'amount': r['amount'],
            'note': ''
        })

    # Admissions billing
    adm_rows = query("""SELECT a.*, p.first_name||' '||p.last_name AS patient_name,
        d.name AS doctor_name, d.department
        FROM admissions a
        JOIN patients p ON p.id=a.patient_id
        LEFT JOIN doctors d ON d.id=a.doctor_id
        ORDER BY a.admit_date DESC""")
    for r in adm_rows:
        records.append({
            'id': f"ADM-{r['id']}",
            'type': 'Admission',
            'patient_name': r['patient_name'],
            'service_name': f"Admission — {r['ward']}" + (f" · {r['room_no']}" if r['room_no'] else ''),
            'department': r['department'] or 'Inpatient',
            'date': r['admit_date'],
            'status': r['status'],
            'amount': r['amount'] or 0,
            'note': r['diagnosis'] or ''
        })

    # Sort all records by date descending
    records.sort(key=lambda x: x['date'] or '', reverse=True)

    total_billed   = sum(r['amount'] for r in records)
    total_collected = sum(r['amount'] for r in records if r['status'] == 'Completed')
    total_pending  = sum(r['amount'] for r in records if r['status'] in ('Pending','Confirmed'))
    total_cancelled = sum(r['amount'] for r in records if r['status'] in ('Cancelled','No-Show'))

    by_type = {}
    for r in records:
        t = r['type']
        by_type[t] = by_type.get(t, 0) + r['amount']

    return jsonify({
        'records': records,
        'summary': {
            'total_billed': round(total_billed, 2),
            'collected': round(total_collected, 2),
            'pending': round(total_pending, 2),
            'cancelled': round(total_cancelled, 2),
            'total_records': len(records),
            'by_type': by_type
        }
    })

@app.route('/api/admin/tables')
def api_admin_tables():
    err = require_login()
    if err: return err
    if session.get('role') != 'admin':
        return jsonify({'error':'Admin only'}), 403
    tables = ['users','departments','doctors','patients','appointments']
    result = {}
    for t in tables:
        count = query(f"SELECT COUNT(*) as c FROM {t}",one=True)['c']
        cols  = [r['name'] for r in query(f"PRAGMA table_info({t})")]
        rows  = query(f"SELECT * FROM {t} ORDER BY id DESC LIMIT 100")
        if t == 'users':
            for r in rows: r['password'] = '••••••••'
        result[t] = {'count':count,'columns':cols,'rows':rows}
    return jsonify(result)

# ── Test email endpoint ───────────────────────────────────────────────────────

# ── Lab Tests API ─────────────────────────────────────────────────────────────

@app.route('/api/lab/tests', methods=['GET','POST'])
def api_lab_tests():
    if request.method == 'POST':
        err = require_login()
        if err: return err
        d = request.json or {}
        nid = execute("INSERT INTO lab_tests (name,category,description,price,turnaround) VALUES (?,?,?,?,?)",
            (d.get('name',''), d.get('category',''), d.get('description',''),
             d.get('price',0), d.get('turnaround','24 hours')))
        return jsonify({'message':'Test added','id':nid}), 201
    cat = request.args.get('category','')
    if cat:
        return jsonify(query("SELECT * FROM lab_tests WHERE category=? AND active=1 ORDER BY name",(cat,)))
    return jsonify(query("SELECT * FROM lab_tests WHERE active=1 ORDER BY category,name"))

@app.route('/api/lab/tests/<int:tid>', methods=['PUT','DELETE'])
def api_lab_test(tid):
    err = require_login()
    if err: return err
    row = query("SELECT * FROM lab_tests WHERE id=?",(tid,),one=True)
    if not row: return jsonify({'error':'Not found'}),404
    if request.method == 'DELETE':
        execute("UPDATE lab_tests SET active=0 WHERE id=?",(tid,))
        return jsonify({'message':'Test removed'})
    d = request.json or {}
    execute("UPDATE lab_tests SET name=?,category=?,description=?,price=?,turnaround=? WHERE id=?",
        (d.get('name',row['name']),d.get('category',row['category']),
         d.get('description',row['description']),d.get('price',row['price']),
         d.get('turnaround',row['turnaround']),tid))
    return jsonify({'message':'Test updated'})

@app.route('/api/lab/bookings', methods=['GET','POST'])
def api_lab_bookings():
    if request.method == 'POST':
        d = request.json or {}
        nid = execute("INSERT INTO lab_bookings (patient_name,patient_contact,patient_email,test_id,test_name,booking_date,booking_time,notes,amount) VALUES (?,?,?,?,?,?,?,?,?)",
            (d.get('patient_name',''),d.get('patient_contact',''),d.get('patient_email'),
             d.get('test_id'),d.get('test_name',''),d.get('booking_date'),
             d.get('booking_time','09:00'),d.get('notes'),d.get('amount',0)))
        return jsonify({'message':'Lab booking confirmed','id':nid}), 201
    return jsonify(query("SELECT * FROM lab_bookings ORDER BY created_at DESC"))

@app.route('/api/lab/bookings/<int:bid>', methods=['PUT','DELETE'])
def api_lab_booking(bid):
    err = require_login()
    if err: return err
    row = query("SELECT * FROM lab_bookings WHERE id=?",(bid,),one=True)
    if not row: return jsonify({'error':'Not found'}),404
    if request.method == 'DELETE':
        execute("DELETE FROM lab_bookings WHERE id=?",(bid,))
        return jsonify({'message':'Booking deleted'})
    d = request.json or {}
    old_status = row['status']
    new_status = d.get('status', old_status)
    new_amount = d.get('amount', row['amount'])
    new_notes  = d.get('notes',  row['notes'])
    execute("UPDATE lab_bookings SET status=?,notes=?,amount=? WHERE id=?",
        (new_status, new_notes, new_amount, bid))

    # Send email when status changes to Confirmed
    if new_status != old_status and row.get('patient_email'):
        if new_status == 'Confirmed':
            html = build_service_booking_email(
                row['patient_name'], row['test_name'], 'Laboratory',
                row['booking_date'], row['booking_time'],
                new_amount, bid)
            send_email_async(row['patient_email'],
                f"✅ Lab Booking Confirmed — {HOSPITAL_NAME}", html)
        elif new_status in ('Completed', 'Cancelled'):
            html = build_service_status_email(
                row['patient_name'], row['test_name'], 'Laboratory',
                row['booking_date'], new_status, bid, new_amount)
            send_email_async(row['patient_email'],
                f"🔬 Lab Booking {new_status} — {HOSPITAL_NAME}", html)

    return jsonify({'message':'Booking updated', 'old_status': old_status, 'new_status': new_status})

# ── Pharmacy (Medicines) API ──────────────────────────────────────────────────

@app.route('/api/pharmacy/medicines', methods=['GET','POST'])
def api_medicines():
    if request.method == 'POST':
        err = require_login()
        if err: return err
        d = request.json or {}
        nid = execute("INSERT INTO medicines (name,category,description,unit_price,stock_qty,reorder_level,supplier,expiry_date) VALUES (?,?,?,?,?,?,?,?)",
            (d.get('name',''),d.get('category',''),d.get('description',''),
             d.get('unit_price',0),d.get('stock_qty',0),d.get('reorder_level',10),
             d.get('supplier'),d.get('expiry_date')))
        return jsonify({'message':'Medicine added','id':nid}), 201
    cat = request.args.get('category','')
    search = request.args.get('search','')
    if search:
        return jsonify(query("SELECT * FROM medicines WHERE active=1 AND (name LIKE ? OR category LIKE ?) ORDER BY name",(f'%{search}%',f'%{search}%')))
    if cat:
        return jsonify(query("SELECT * FROM medicines WHERE category=? AND active=1 ORDER BY name",(cat,)))
    return jsonify(query("SELECT * FROM medicines WHERE active=1 ORDER BY category,name"))

@app.route('/api/pharmacy/medicines/<int:mid>', methods=['PUT','DELETE'])
def api_medicine(mid):
    err = require_login()
    if err: return err
    row = query("SELECT * FROM medicines WHERE id=?",(mid,),one=True)
    if not row: return jsonify({'error':'Not found'}),404
    if request.method == 'DELETE':
        execute("UPDATE medicines SET active=0 WHERE id=?",(mid,))
        return jsonify({'message':'Medicine removed'})
    d = request.json or {}
    execute("UPDATE medicines SET name=?,category=?,description=?,unit_price=?,stock_qty=?,reorder_level=?,supplier=?,expiry_date=? WHERE id=?",
        (d.get('name',row['name']),d.get('category',row['category']),
         d.get('description',row['description']),d.get('unit_price',row['unit_price']),
         d.get('stock_qty',row['stock_qty']),d.get('reorder_level',row['reorder_level']),
         d.get('supplier',row['supplier']),d.get('expiry_date',row['expiry_date']),mid))
    return jsonify({'message':'Medicine updated'})

# ── Radiology Services API ────────────────────────────────────────────────────

@app.route('/api/radiology/services', methods=['GET','POST'])
def api_radiology_services():
    if request.method == 'POST':
        err = require_login()
        if err: return err
        d = request.json or {}
        nid = execute("INSERT INTO radiology_services (name,modality,description,price,preparation,duration_minutes) VALUES (?,?,?,?,?,?)",
            (d.get('name',''),d.get('modality',''),d.get('description',''),
             d.get('price',0),d.get('preparation',''),d.get('duration_minutes',30)))
        return jsonify({'message':'Service added','id':nid}), 201
    modality = request.args.get('modality','')
    if modality:
        return jsonify(query("SELECT * FROM radiology_services WHERE modality=? AND active=1 ORDER BY name",(modality,)))
    return jsonify(query("SELECT * FROM radiology_services WHERE active=1 ORDER BY modality,name"))

@app.route('/api/radiology/services/<int:sid>', methods=['PUT','DELETE'])
def api_radiology_service(sid):
    err = require_login()
    if err: return err
    row = query("SELECT * FROM radiology_services WHERE id=?",(sid,),one=True)
    if not row: return jsonify({'error':'Not found'}),404
    if request.method == 'DELETE':
        execute("UPDATE radiology_services SET active=0 WHERE id=?",(sid,))
        return jsonify({'message':'Service removed'})
    d = request.json or {}
    execute("UPDATE radiology_services SET name=?,modality=?,description=?,price=?,preparation=?,duration_minutes=? WHERE id=?",
        (d.get('name',row['name']),d.get('modality',row['modality']),
         d.get('description',row['description']),d.get('price',row['price']),
         d.get('preparation',row['preparation']),d.get('duration_minutes',row['duration_minutes']),sid))
    return jsonify({'message':'Service updated'})

@app.route('/api/radiology/bookings', methods=['GET','POST'])
def api_radiology_bookings():
    if request.method == 'POST':
        d = request.json or {}
        nid = execute("INSERT INTO radiology_bookings (patient_name,patient_contact,patient_email,service_id,service_name,booking_date,booking_time,notes,amount) VALUES (?,?,?,?,?,?,?,?,?)",
            (d.get('patient_name',''),d.get('patient_contact',''),d.get('patient_email'),
             d.get('service_id'),d.get('service_name',''),d.get('booking_date'),
             d.get('booking_time','09:00'),d.get('notes'),d.get('amount',0)))
        return jsonify({'message':'Radiology booking confirmed','id':nid}), 201
    return jsonify(query("SELECT * FROM radiology_bookings ORDER BY created_at DESC"))

@app.route('/api/radiology/bookings/<int:bid>', methods=['PUT','DELETE'])
def api_radiology_booking(bid):
    err = require_login()
    if err: return err
    row = query("SELECT * FROM radiology_bookings WHERE id=?",(bid,),one=True)
    if not row: return jsonify({'error':'Not found'}),404
    if request.method == 'DELETE':
        execute("DELETE FROM radiology_bookings WHERE id=?",(bid,))
        return jsonify({'message':'Booking deleted'})
    d = request.json or {}
    old_status = row['status']
    new_status = d.get('status', old_status)
    new_amount = d.get('amount', row['amount'])
    new_notes  = d.get('notes',  row['notes'])
    execute("UPDATE radiology_bookings SET status=?,notes=?,amount=? WHERE id=?",
        (new_status, new_notes, new_amount, bid))

    # Send email when status changes to Confirmed
    if new_status != old_status and row.get('patient_email'):
        # Get preparation instructions from service
        svc = query("SELECT preparation FROM radiology_services WHERE id=?",(row['service_id'],),one=True)
        prep = svc['preparation'] if svc else ''
        if new_status == 'Confirmed':
            html = build_service_booking_email(
                row['patient_name'], row['service_name'], 'Radiology',
                row['booking_date'], row['booking_time'],
                new_amount, bid, prep)
            send_email_async(row['patient_email'],
                f"✅ Radiology Booking Confirmed — {HOSPITAL_NAME}", html)
        elif new_status in ('Completed', 'Cancelled'):
            html = build_service_status_email(
                row['patient_name'], row['service_name'], 'Radiology',
                row['booking_date'], new_status, bid, new_amount)
            send_email_async(row['patient_email'],
                f"📡 Radiology Booking {new_status} — {HOSPITAL_NAME}", html)

    return jsonify({'message':'Booking updated', 'old_status': old_status, 'new_status': new_status})

# ── Test email endpoint ───────────────────────────────────────────────────────
@app.route('/api/test-email', methods=['POST'])
def test_email():
    err = require_login()
    if err: return err
    d = request.json or {}
    to = d.get('email','')
    if not to: return jsonify({'error':'Email required'}), 400
    html = build_confirmation_email('Test Patient','Dr. Sample','Cardiology',
        date.today().strftime('%Y-%m-%d'),'10:00 AM','Test consultation',999)
    send_email_async(to, f'✅ Test Email — {HOSPITAL_NAME}', html)
    return jsonify({'message':f'Test email sent to {to} (check spam if not received)'})


# ── Email Settings (Admin) ────────────────────────────────────────────────────

@app.route('/api/email/config', methods=['GET', 'POST'])
def api_email_config():
    err = require_login()
    if err: return err
    if session.get('role') != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    if request.method == 'POST':
        d = request.json or {}
        cfg = {
            'enabled':  d.get('enabled', False),
            'username': d.get('username', '').strip(),
            'password': d.get('password', '').strip(),
            'provider': d.get('provider', 'gmail'),
        }
        save_email_config(cfg)
        return jsonify({'message': 'Email settings saved'})
    cfg = load_email_config()
    # Mask password for display
    safe = dict(cfg)
    if safe.get('password'):
        safe['password'] = '••••••••'
        safe['has_password'] = True
    else:
        safe['has_password'] = False
    return jsonify(safe)

@app.route('/api/email/test', methods=['POST'])
def api_email_test():
    err = require_login()
    if err: return err
    d = request.json or {}
    to = d.get('email', '').strip()
    if not to or '@' not in to:
        return jsonify({'error': 'Valid email required'}), 400
    username, password, enabled = get_mail_settings()

    # Detailed pre-flight checks
    if not enabled:
        return jsonify({'error': 'STEP 1 FAILED: Email notifications are disabled. Toggle the switch ON first.'}), 400
    if not username:
        return jsonify({'error': 'STEP 2 FAILED: No Gmail address entered. Enter your Gmail and Save.'}), 400
    if not password:
        return jsonify({'error': 'STEP 3 FAILED: No App Password saved. Enter your 16-letter App Password and Save.'}), 400
    if '@gmail.com' not in username and '@googlemail.com' not in username:
        return jsonify({'error': f'WARNING: {username} may not be a Gmail address. Only Gmail SMTP is supported.'}), 400

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'✅ MediCare Plus — Email Test Successful'
        msg['From']    = f'{HOSPITAL_NAME} <{username}>'
        msg['To']      = to
        html_body = build_confirmation_email(
            'Test Patient', 'Dr. Sample Doctor', 'Cardiology',
            date.today().strftime('%Y-%m-%d'), '10:00 AM',
            'This is a test email to verify your settings work.', 0)
        msg.attach(MIMEText(html_body, 'html'))

        print(f"📧 Attempting SMTP connection to {MAIL_HOST}:{MAIL_PORT}...")
        with smtplib.SMTP(MAIL_HOST, MAIL_PORT, timeout=20) as server:
            server.set_debuglevel(0)
            server.ehlo()
            print("📧 EHLO ok, starting TLS...")
            server.starttls()
            server.ehlo()
            print(f"📧 TLS ok, logging in as {username}...")
            server.login(username, password)
            print(f"📧 Login ok, sending to {to}...")
            server.sendmail(username, to, msg.as_string())
            print(f"✅ Email delivered to {to}")

        return jsonify({
            'message': f'✅ Email sent to {to}! Check your inbox (and spam/junk folder).',
            'from': username,
            'to': to
        })

    except smtplib.SMTPAuthenticationError as e:
        msg_detail = str(e)
        if '534' in msg_detail or '535' in msg_detail:
            return jsonify({'error': (
                'Authentication failed (535). This means:\n'
                '• You used your normal Gmail password — this does NOT work\n'
                '• You need a Gmail APP PASSWORD (16 letters with spaces)\n\n'
                'How to get one:\n'
                '1. Go to myaccount.google.com/security\n'
                '2. Enable 2-Step Verification\n'
                '3. Search "App passwords" → Generate → Mail → Copy 16 letters\n'
                '4. Paste it in the App Password field above'
            )}), 400
        return jsonify({'error': f'Authentication error: {msg_detail}'}), 400
    except smtplib.SMTPConnectError as e:
        return jsonify({'error': f'Cannot connect to Gmail SMTP. Check your internet connection. ({e})'}), 400
    except smtplib.SMTPRecipientsRefused as e:
        return jsonify({'error': f'Recipient email refused: {to}. Check the address is valid.'}), 400
    except Exception as e:
        return jsonify({'error': f'Error: {type(e).__name__}: {str(e)}'}), 500

# ── App init — runs for both  `python app.py`  and  gunicorn  ─────────────────
def _migrate_doctor_users():
    """One-time migration: create user accounts for any doctor that doesn't have one yet."""
    try:
        doctors = query("SELECT id, name, email FROM doctors ORDER BY id")
        created = 0
        for doc in doctors:
            try:
                result = create_doctor_user(doc['id'], doc['name'], doc.get('email'))
                if result:
                    created += 1
                    print(f"  ✅ Created login for {doc['name']} → {result['username']} / {result['password']}")
            except Exception as e:
                print(f"  ⚠️ Skipped {doc['name']}: {e}")
        if created:
            print(f"  🎉 Auto-migration: created {created} doctor login accounts")
    except Exception as e:
        print(f"  ⚠️ Doctor migration skipped: {e}")

def _init():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)   # ensure /data exists on Railway volume
    create_tables()
    # Migration: add hidden column to departments if it doesn't exist
    try:
        execute("ALTER TABLE departments ADD COLUMN hidden INTEGER DEFAULT 0")
    except Exception:
        pass  # column already exists
    seed_database()
    _migrate_doctor_users()   # safe to run every startup — skips existing accounts

_init()   # called at import time so gunicorn picks it up automatically

# ── Startup (direct run only) ─────────────────────────────────────────────────
if __name__ == '__main__':
    is_dev = os.environ.get('FLASK_ENV', 'production') != 'production'
    port   = int(os.environ.get('PORT', 5000))
    print(f"\n{'='*55}")
    print("  🏥  MediCare Plus — Hospital Management System")
    print(f"{'='*55}")
    print(f"  📂  Database : {DB_PATH}")
    print(f"  🌐  Open     : http://localhost:{port}")
    print(f"  🔒  Mode     : {'DEVELOPMENT ⚠️' if is_dev else 'PRODUCTION ✅'}")
    print(f"{'='*55}\n")
    app.run(debug=is_dev, host='0.0.0.0', port=port)