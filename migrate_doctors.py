"""
migrate_doctors.py
==================
Run once to:
  1. Add `doctor_id` column to the `users` table (if missing)
  2. Create a login account for every doctor who doesn't have one yet

Usage (local):
    python migrate_doctors.py

On Railway:
    Add to your Procfile or run as a one-off command in the Railway shell:
    python migrate_doctors.py

Credentials generated:
    username : dr_<firstname><lastname>   e.g.  dr_sarahwilson
    password : <firstname>#<doctor_id>    e.g.  sarah#1
    role     : doctor
"""

import sqlite3, hashlib, os

# ── resolve DB path the same way app.py does ────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_db_env  = os.environ.get('DB_PATH', '').strip()
DB_PATH  = _db_env if _db_env else os.path.join(BASE_DIR, 'hospital.db')

print(f"📂  Database : {DB_PATH}")

def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def generate_credentials(name: str, doctor_id: int):
    """
    'Dr. Sarah Wilson', 1  →  ('dr_sarahwilson', 'sarah#1')
    'Dr.smith',        37  →  ('dr_smith',       'smith#37')
    """
    clean = name.lower().replace('dr.', '').replace('dr ', '').strip()
    parts = clean.split() or ['doctor']
    username = 'dr_' + ''.join(parts)
    password = f"{parts[0]}#{doctor_id}"
    return username, password

def run_migration():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    # ── Step 1: add doctor_id column if missing ──────────────────────────────
    existing_cols = [r['name'] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
    if 'doctor_id' not in existing_cols:
        conn.execute("ALTER TABLE users ADD COLUMN doctor_id INTEGER REFERENCES doctors(id)")
        conn.commit()
        print("✅  Added 'doctor_id' column to users table")
    else:
        print("ℹ️   'doctor_id' column already exists — skipping ALTER TABLE")

    # ── Step 2: collect all doctors ─────────────────────────────────────────
    doctors = conn.execute("SELECT id, name, email FROM doctors ORDER BY id").fetchall()
    print(f"\n👨‍⚕️  Found {len(doctors)} doctors\n")

    created   = []
    skipped   = []
    used_unames = set(
        r['username'] for r in conn.execute("SELECT username FROM users").fetchall()
    )

    for doc in doctors:
        did   = doc['id']
        name  = doc['name']
        email = doc['email']

        # Already linked?
        linked = conn.execute(
            "SELECT id FROM users WHERE doctor_id=?", (did,)
        ).fetchone()
        if linked:
            skipped.append(name)
            continue

        # Generate credentials — handle username collision
        username, password = generate_credentials(name, did)
        if username in used_unames:
            clean = name.lower().replace('dr.','').replace('dr ','').strip()
            parts = clean.split() or ['doctor']
            username = f"dr_{parts[0]}{did}"   # e.g. dr_james32
        used_unames.add(username)

        # Derive email
        doc_email = (email or '').strip() or f"{username}@medicare.com"
        # Ensure email uniqueness
        if conn.execute("SELECT id FROM users WHERE email=?", (doc_email,)).fetchone():
            doc_email = f"{username}{did}@medicare.com"

        conn.execute(
            "INSERT INTO users (username, email, password, role, full_name, doctor_id) "
            "VALUES (?, ?, ?, 'doctor', ?, ?)",
            (username, doc_email, hash_pw(password), name, did)
        )
        conn.commit()
        created.append({
            'id':       did,
            'name':     name,
            'username': username,
            'password': password,
            'email':    doc_email,
        })

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"{'ID':<5} {'Doctor':<25} {'Username':<25} {'Password':<20} {'Email'}")
    print("─" * 100)
    for c in created:
        print(f"{c['id']:<5} {c['name']:<25} {c['username']:<25} {c['password']:<20} {c['email']}")

    print(f"\n✅  Created {len(created)} doctor login accounts")
    if skipped:
        print(f"⏭️   Skipped {len(skipped)} (already had accounts): {', '.join(skipped)}")

    conn.close()
    print("\n🎉  Migration complete!\n")
    print("Doctors can now log in with:")
    print("  Username : dr_<firstname><lastname>  (e.g. dr_sarahwilson)")
    print("  Password : <firstname>#<doctor_id>  (e.g. sarah#1)")

if __name__ == '__main__':
    run_migration()
