"""
Admin Panel - Code-Only Access
No Google login required - just enter a valid admin code
"""
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, current_app
from functools import wraps
from datetime import datetime
import os
import uuid

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

def get_cursor(conn, db_type):
    """Get cursor with dict-like access"""
    if db_type == 'postgres':
        import psycopg2.extras
        return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        conn.row_factory = sqlite3.Row
        return conn.cursor()

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
        c = get_cursor(conn, db_type)
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
    except Exception as e:
        print(f"[ERROR] Failed to log action: {e}")
    finally:
        conn.close()

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
    import sqlite3
    try:
        conn, db_type = get_db()
        
        users = 0
        bans = 0
        views = 0
        verses = 0
        
        try:
            c = conn.cursor()
            
            # Users count
            c.execute("SELECT COUNT(*) FROM users")
            row = c.fetchone()
            if row:
                users = row[0] if isinstance(row, (list, tuple)) else row['count'] if hasattr(row, 'keys') else 0
            
            # Bans count
            c.execute("SELECT COUNT(*) FROM bans")
            row = c.fetchone()
            if row:
                bans = row[0] if isinstance(row, (list, tuple)) else row['count'] if hasattr(row, 'keys') else 0
            
            # Also check users table
            c.execute("SELECT COUNT(*) FROM users WHERE is_banned = 1")
            row = c.fetchone()
            banned_users = 0
            if row:
                banned_users = row[0] if isinstance(row, (list, tuple)) else row['count'] if hasattr(row, 'keys') else 0
            
            total_bans = max(bans, banned_users)
            
            # Verse views
            c.execute("SELECT COALESCE(SUM(views), 0) FROM verses")
            row = c.fetchone()
            if row:
                views = row[0] if isinstance(row, (list, tuple)) else row[0] if hasattr(row, 'keys') else 0
            
            # Total verses
            c.execute("SELECT COUNT(*) FROM verses")
            row = c.fetchone()
            if row:
                verses = row[0] if isinstance(row, (list, tuple)) else row['count'] if hasattr(row, 'keys') else 0
                
        except Exception as e:
            print(f"[ERROR] Query error: {e}")
        finally:
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
        c.execute("SELECT id, name, email, role, is_admin, is_banned, created_at FROM users ORDER BY created_at DESC")
        rows = c.fetchall()
        conn.close()
        
        users = []
        for row in rows:
            try:
                if hasattr(row, 'keys'):
                    user = {
                        "id": row["id"],
                        "name": row["name"],
                        "email": row["email"],
                        "role": row["role"] or "user",
                        "is_admin": bool(row["is_admin"]),
                        "is_banned": bool(row["is_banned"]),
                        "created_at": row["created_at"]
                    }
                else:
                    user = {
                        "id": row[0],
                        "name": row[1],
                        "email": row[2],
                        "role": row[3] or "user",
                        "is_admin": bool(row[4]),
                        "is_banned": bool(row[5]),
                        "created_at": row[6]
                    }
            except Exception as e:
                print(f"[ERROR] Processing user row: {e}, row: {row}")
                continue
            users.append(user)
        return jsonify(users)
    except Exception as e:
        print(f"[ERROR] Get users: {e}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/bans')
@admin_required
def get_bans():
    """Get all banned users with details"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Get bans with user info
        c.execute("""
            SELECT b.id, b.user_id, b.reason, b.banned_by, b.banned_at, b.expires_at,
                   u.name, u.email
            FROM bans b
            JOIN users u ON b.user_id = u.id
            ORDER BY b.banned_at DESC
        """)
        
        rows = c.fetchall()
        conn.close()
        
        bans = []
        for row in rows:
            try:
                if hasattr(row, 'keys'):
                    ban = {
                        "id": row["id"],
                        "user_id": row["user_id"],
                        "reason": row["reason"],
                        "banned_by": row["banned_by"],
                        "banned_at": row["banned_at"],
                        "expires_at": row["expires_at"],
                        "user_name": row["name"],
                        "user_email": row["email"]
                    }
                else:
                    ban = {
                        "id": row[0],
                        "user_id": row[1],
                        "reason": row[2],
                        "banned_by": row[3],
                        "banned_at": row[4],
                        "expires_at": row[5],
                        "user_name": row[6],
                        "user_email": row[7]
                    }
            except Exception as e:
                print(f"[ERROR] Processing ban row: {e}")
                continue
            bans.append(ban)
        return jsonify(bans)
    except Exception as e:
        print(f"[ERROR] Get bans: {e}")
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
        
        current_role = row[0] if row[0] else "user"
        
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
        
        # Get target user
        c.execute("SELECT role, is_admin, name FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        target_role = row[0] if row[0] else "user"
        user_name = row[2] if len(row) > 2 else "Unknown"
        
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
        c.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100")
        rows = c.fetchall()
        conn.close()
        
        logs = []
        for row in rows:
            try:
                if hasattr(row, 'keys'):
                    log = {
                        "id": row["id"],
                        "admin_id": row["admin_id"],
                        "action": row["action"],
                        "details": row["details"],
                        "ip_address": row["ip_address"],
                        "timestamp": row["timestamp"]
                    }
                else:
                    log = {
                        "id": row[0],
                        "admin_id": row[1],
                        "action": row[2],
                        "details": row[3],
                        "ip_address": row[4],
                        "timestamp": row[5]
                    }
            except:
                continue
            logs.append(log)
        return jsonify(logs)
    except Exception as e:
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
