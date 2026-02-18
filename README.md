# MediCare Plus — Hospital Management System
## Full Version: SQLite DB + Auth + Reports + DB Viewer

---

## HOW TO RUN

**Windows:** Double-click `START_WINDOWS.bat` → open http://localhost:5000
**Mac/Linux:** `./START_MAC_LINUX.sh` → open http://localhost:5000
**Manual:** `pip install flask` then `python app.py`

---

## DEFAULT LOGIN ACCOUNTS

| Role  | Username | Password  |
|-------|----------|-----------|
| Admin | admin    | admin123  |
| Staff | doctor1  | doctor123 |
| Staff | staff1   | staff123  |

**Change passwords after first login!** (Admin Panel → User Management)

---

## FEATURES

### 1. Permanent SQLite Database
- File: `hospital.db` (auto-created on first run)
- All data survives server restarts
- Backup = just copy hospital.db

### 2. Login & Access Control
- Must login to Add/Edit/Book/Cancel anything
- Wrong password = blocked
- Admin can create/delete staff accounts
- Guest (not logged in) can VIEW only

### 3. Live Database Counts
- Dashboard stats pulled from DB in real time
- Patient count only increases when you actually add a patient
- Appointment counts update instantly after booking/cancelling

### 4. Generate Reports (4 types)
- Patient Report: demographics, blood groups, appointment counts
- Appointment Report: all bookings, status breakdown, by department
- Department Report: doctor count, appointment volume per department
- Financial Report: billing summary, collected vs pending

### 5. Database Viewer (Admin only)
- Admin Panel → Database Viewer
- See ALL tables live: users, patients, doctors, appointments, departments
- Row counts, searchable data, colour-coded status
- Passwords hidden for security

### 6. User Management (Admin only)
- Admin Panel → User Management
- Create new staff/admin accounts
- Delete accounts (cannot delete yourself)

---

## DATABASE TABLES

| Table        | Description                     |
|--------------|---------------------------------|
| users        | Login accounts (hashed passwords)|
| patients     | Patient records                 |
| doctors      | 36 doctors across 12 depts      |
| appointments | Bookings with status            |
| departments  | 12 medical departments          |

---

## API ENDPOINTS

| Method | Endpoint | Auth? | Description |
|--------|----------|-------|-------------|
| POST | /api/auth/login | No | Login |
| POST | /api/auth/logout | No | Logout |
| GET | /api/auth/me | No | Check session |
| GET | /api/dashboard/stats | No | Live counts |
| GET/POST | /api/patients | GET:No / POST:Yes | Patients |
| GET/POST | /api/appointments | GET:No / POST:Yes | Appointments |
| PUT | /api/appointments/<id> | Yes | Cancel/update |
| GET | /api/doctors | No | Doctors |
| GET | /api/departments | No | Departments |
| GET | /api/reports/patients | No | Patient report |
| GET | /api/reports/appointments | No | Appt report |
| GET | /api/reports/departments | No | Dept report |
| GET | /api/reports/financial | No | Financial report |
| GET | /api/admin/tables | Admin | DB viewer data |
| GET/POST | /api/users | Admin | User management |

