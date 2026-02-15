"""
Admin Panel - Code-Only Access
Fixed database queries and error handling
"""
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, current_app
from functools import wraps
from datetime import datetime
import os
import sqlite3

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Role hierarchy (higher number = more power)
ROLE_HIERARCHY = {
    'user': 0,
    'host': 1,
    'mod': 2,
    'co_owner': 3,
    'owner': 4
}

ROLE_CODES = {
    'host': os.environ.get('HOST_CODE', 'HOST123'),
    'mod': os.environ.get('MOD_CODE', 'MOD456'),
    'co_owner': os.environ.get('CO_OWNER_CODE', 'COOWNER789'),
    'owner': os.environ.get('OWNER_CODE', 'OWNER999')
}

def get_db():
    """Get database connection"""
    from app import get_db as app_get_db
    return app_get_db()

def get_admin_session():
    """Get admin session info if logged in via code"""
    if 'admin_role' not in session:
        return None
    return {
        'role': session.get('admin_role'),
        'level': ROLE_HIERARCHY.get(session.get('admin_role'), 0),
        'code': session.get('admin_code')
    }

def admin_required(f):
    """Decorator to require valid admin code"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin = get_admin_session()
        if not admin:
            if request.is_json:
                return jsonify({"error": "Admin login required"}), 401
            return redirect(url_for('admin.admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def can_modify_role(admin_role, target_role):
    """Check if admin can modify target role"""
    admin_level = ROLE_HIERARCHY.get(admin_role, 0)
    target_level = ROLE_HIERARCHY.get(target_role, 0)
    return admin_level > target_level

def log_action(action, details=""):
    """Log admin action"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        admin = get_admin_session()
        admin_id = admin['role'] if admin else 'unknown'
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if db_type == 'postgres':
            c.execute("""
                INSERT INTO audit_logs (admin_id, action, details, ip_address, timestamp)
                VALUES (%s, %s, %s, %s, %s)
            """, (admin_id, action, details, request.remote_addr, timestamp))
        else:
            c.execute("""
                INSERT INTO audit_logs (admin_id, action, details, ip_address, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (admin_id, action, details, request.remote_addr, timestamp))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Failed to log action: {e}")

# === ROUTES ===

@admin_bp.route('/login')
def admin_login():
    """Admin login page - code only"""
    if get_admin_session():
        return redirect(url_for('admin.admin_dashboard'))
    return render_template('admin_login_simple.html')

@admin_bp.route('/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    return render_template('admin_dashboard.html')

@admin_bp.route('/logout', methods=['POST'])
def admin_logout():
    """Logout admin"""
    session.pop('admin_role', None)
    session.pop('admin_code', None)
    return redirect(url_for('admin.admin_login'))

# === API ENDPOINTS ===

@admin_bp.route('/api/verify-code', methods=['POST'])
def verify_code():
    """Verify admin code and grant access"""
    data = request.get_json()
    code = data.get('code', '').strip()
    
    if not code:
        return jsonify({"success": False, "error": "Code required"}), 400
    
    # Check against role codes
    for role, role_code in ROLE_CODES.items():
        if code == role_code:
            # Valid code - create session
            session['admin_role'] = role
            session['admin_code'] = code
            log_action("ADMIN_LOGIN", f"Role: {role}")
            return jsonify({
                "success": True,
                "role": role,
                "redirect": "/admin/dashboard"
            })
    
    # Invalid code
    return jsonify({"success": False, "error": "Invalid code"}), 401

@admin_bp.route('/api/stats')
@admin_required
def get_stats():
    """Get dashboard stats"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Users count
        c.execute("SELECT COUNT(*) FROM users")
        row = c.fetchone()
        users = row[0] if row else 0
        
        # Bans count
        c.execute("SELECT COUNT(*) FROM bans")
        row = c.fetchone()
        bans = row[0] if row else 0
        
        # Also check users table for banned users
        c.execute("SELECT COUNT(*) FROM users WHERE is_banned = 1")
        row = c.fetchone()
        banned_users = row[0] if row else 0
        
        total_bans = max(bans, banned_users)
        
        # Verse views - handle if views column doesn't exist
        try:
            c.execute("SELECT COALESCE(SUM(views), 0) FROM verses")
            row = c.fetchone()
            views = row[0] if row else 0
        except:
            views = 0
        
        # Total verses
        c.execute("SELECT COUNT(*) FROM verses")
        row = c.fetchone()
        verses = row[0] if row else 0
        
        conn.close()
        
        admin = get_admin_session()
        return jsonify({
            "users": users,
            "bans": total_bans,
            "views": views,
            "verses": verses,
            "role": admin['role'],
            "level": admin['level']
        })
    except Exception as e:
        import traceback
        print(f"[ERROR] Stats error: {e}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/users')
@admin_required
def get_users():
    """Get all users"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        c.execute("SELECT id, name, email, role, is_admin, is_banned, created_at FROM users ORDER BY id DESC")
        rows = c.fetchall()
        conn.close()
        
        users = []
        for row in rows:
            try:
                user = {
                    "id": row[0],
                    "name": row[1] or "Unknown",
                    "email": row[2] or "No email",
                    "role": row[3] or "user",
                    "is_admin": bool(row[4]) if row[4] else False,
                    "is_banned": bool(row[5]) if row[5] else False,
                    "created_at": row[6] or "Unknown"
                }
                users.append(user)
            except Exception as e:
                print(f"[ERROR] Processing user row {row}: {e}")
                continue
        
        return jsonify(users)
    except Exception as e:
        import traceback
        print(f"[ERROR] Get users: {e}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/bans')
@admin_required
def get_bans():
    """Get all banned users with details"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Check if bans table exists
        try:
            c.execute("SELECT 1 FROM bans LIMIT 1")
        except:
            # Table doesn't exist, create it
            c.execute("""
                CREATE TABLE IF NOT EXISTS bans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER UNIQUE,
                    reason TEXT,
                    banned_by TEXT,
                    banned_at TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
            return jsonify([])
        
        # Get bans with user info
        c.execute("""
            SELECT b.id, b.user_id, b.reason, b.banned_by, b.banned_at, b.expires_at,
                   u.name, u.email
            FROM bans b
            LEFT JOIN users u ON b.user_id = u.id
            ORDER BY b.banned_at DESC
        """)
        
        rows = c.fetchall()
        conn.close()
        
        bans = []
        for row in rows:
            try:
                ban = {
                    "id": row[0],
                    "user_id": row[1],
                    "reason": row[2] or "No reason",
                    "banned_by": row[3] or "Unknown",
                    "banned_at": row[4],
                    "expires_at": row[5],
                    "user_name": row[6] or "Unknown",
                    "user_email": row[7] or "No email"
                }
                bans.append(ban)
            except Exception as e:
                print(f"[ERROR] Processing ban row {row}: {e}")
                continue
        
        return jsonify(bans)
    except Exception as e:
        import traceback
        print(f"[ERROR] Get bans: {e}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/users/<int:user_id>/role', methods=['POST'])
@admin_required
def update_user_role(user_id):
    """Update user role"""
    admin = get_admin_session()
    data = request.get_json()
    new_role = data.get('role')
    
    if not new_role or new_role not in ROLE_HIERARCHY:
        return jsonify({"error": "Invalid role"}), 400
    
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Get target user's current role
        c.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        current_role = row[0] or "user"
        
        # Check permissions
        if not can_modify_role(admin['role'], current_role):
            conn.close()
            return jsonify({"error": "Cannot modify users of this role"}), 403
        
        if not can_modify_role(admin['role'], new_role):
            conn.close()
            return jsonify({"error": "Cannot assign this role"}), 403
        
        # Update
        is_admin = 1 if ROLE_HIERARCHY[new_role] > 0 else 0
        c.execute("UPDATE users SET role = ?, is_admin = ? WHERE id = ?", 
                 (new_role, is_admin, user_id))
        conn.commit()
        conn.close()
        
        log_action("UPDATE_ROLE", f"User {user_id} to {new_role}")
        return jsonify({"success": True})
        
    except Exception as e:
        import traceback
        print(f"[ERROR] Update role: {e}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/users/<int:user_id>/ban', methods=['POST'])
@admin_required
def ban_user(user_id):
    """Ban/unban user"""
    admin = get_admin_session()
    data = request.get_json()
    banned = data.get('banned', True)
    reason = data.get('reason', 'No reason provided')
    
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Ensure bans table exists
        c.execute("""
            CREATE TABLE IF NOT EXISTS bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE,
                reason TEXT,
                banned_by TEXT,
                banned_at TIMESTAMP,
                expires_at TIMESTAMP
            )
        """)
        
        # Get target user
        c.execute("SELECT role, name FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        target_role = row[0] or "user"
        user_name = row[1] or "Unknown"
        
        # Cannot ban higher or equal roles
        if not can_modify_role(admin['role'], target_role):
            conn.close()
            return jsonify({"error": "Cannot ban this user"}), 403
        
        if banned:
            # Ban the user
            c.execute("UPDATE users SET is_banned = 1 WHERE id = ?", (user_id,))
            
            # Add to bans table
            c.execute("""
                INSERT OR REPLACE INTO bans (user_id, reason, banned_by, banned_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, reason, admin['role'], datetime.now().isoformat(), None))
            
            log_action("BAN", f"Banned user {user_name} ({user_id}): {reason}")
        else:
            # Unban the user
            c.execute("UPDATE users SET is_banned = 0 WHERE id = ?", (user_id,))
            
            # Remove from bans table
            c.execute("DELETE FROM bans WHERE user_id = ?", (user_id,))
            
            log_action("UNBAN", f"Unbanned user {user_name} ({user_id})")
        
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "banned": banned})
        
    except Exception as e:
        import traceback
        print(f"[ERROR] Ban error: {e}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/audit-logs')
@admin_required
def get_audit_logs():
    """Get audit logs"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Ensure audit_logs table exists
        try:
            c.execute("SELECT 1 FROM audit_logs LIMIT 1")
        except:
            c.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    admin_id TEXT,
                    action TEXT,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
            return jsonify([])
        
        c.execute("SELECT id, admin_id, action, details, ip_address, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 100")
        rows = c.fetchall()
        conn.close()
        
        logs = []
        for row in rows:
            try:
                log = {
                    "id": row[0],
                    "admin_id": row[1] or "system",
                    "action": row[2] or "UNKNOWN",
                    "details": row[3] or "",
                    "ip_address": row[4] or "",
                    "timestamp": row[5]
                }
                logs.append(log)
            except Exception as e:
                print(f"[ERROR] Processing log row {row}: {e}")
                continue
        
        return jsonify(logs)
    except Exception as e:
        import traceback
        print(f"[ERROR] Get audit logs: {e}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/settings', methods=['GET', 'POST'])
@admin_required
def settings():
    """Get/update settings"""
    admin = get_admin_session()
    
    if request.method == 'GET':
        return jsonify({
            "site_name": os.environ.get('SITE_NAME', 'AI.Bible'),
            "maintenance_mode": os.environ.get('MAINTENANCE_MODE', 'false'),
            "codes": ROLE_CODES,
            "role": admin['role']
        })
    
    # POST - update settings (owner only)
    if admin['role'] != 'owner':
        return jsonify({"error": "Owner access required"}), 403
    
    data = request.get_json()
    log_action("UPDATE_SETTINGS", "Settings updated")
    return jsonify({"success": True})

@admin_bp.route('/api/check-session')
def check_session():
    """Check if admin session is valid"""
    admin = get_admin_session()
    if admin:
        return jsonify({"logged_in": True, "role": admin['role']})
    return jsonify({"logged_in": False}), 401
