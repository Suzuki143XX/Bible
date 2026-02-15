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
        return conn.cursor()
    else:
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
    """Get dashboard stats - FIXED to properly fetch data"""
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        # Users count - FIX: fetch once
        c.execute("SELECT COUNT(*) as count FROM users")
        row = c.fetchone()
        users = 0
        if row:
            try:
                users = row['count'] if isinstance(row, dict) else row[0]
            except:
                users = 0
        
        # Bans count from bans table - FIX: fetch once
        c.execute("SELECT COUNT(*) as count FROM bans")
        row = c.fetchone()
        bans = 0
        if row:
            try:
                bans = row['count'] if isinstance(row, dict) else row[0]
            except:
                bans = 0
        
        # Also count users with is_banned=1 - FIX: fetch once
        c.execute("SELECT COUNT(*) as count FROM users WHERE is_banned = 1")
        row = c.fetchone()
        banned_users = 0
        if row:
            try:
                banned_users = row['count'] if isinstance(row, dict) else row[0]
            except:
                banned_users = 0
        
        # Use the larger of the two ban counts
        total_bans = max(bans, banned_users)
        
        # Verse views - FIX: fetch once
        c.execute("SELECT COALESCE(SUM(views), 0) as total FROM verses")
        row = c.fetchone()
        views = 0
        if row:
            try:
                views = row['total'] if isinstance(row, dict) else row[0]
            except:
                views = 0
        
        # Total verses - FIX: fetch once
        c.execute("SELECT COUNT(*) as count FROM verses")
        row = c.fetchone()
        total_verses = 0
        if row:
            try:
                total_verses = row['count'] if isinstance(row, dict) else row[0]
            except:
                total_verses = 0
        
        conn.close()
        
        admin = get_admin_session()
        return jsonify({
            "users": users,
            "bans": total_bans,
            "views": views,
            "verses": total_verses,
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
        c = get_cursor(conn, db_type)
        c.execute("SELECT id, name, email, role, is_admin, is_banned, created_at FROM users ORDER BY created_at DESC")
        rows = c.fetchall()
        conn.close()
        
        users = []
        for row in rows:
            try:
                user = {
                    "id": row["id"],
                    "name": row["name"],
                    "email": row["email"],
                    "role": row["role"] or "user",
                    "is_admin": bool(row["is_admin"]),
                    "is_banned": bool(row["is_banned"]),
                    "created_at": row["created_at"]
                }
            except:
                user = {
                    "id": row[0],
                    "name": row[1],
                    "email": row[2],
                    "role": row[3] or "user",
                    "is_admin": bool(row[4]),
                    "is_banned": bool(row[5]),
                    "created_at": row[6]
                }
            users.append(user)
        return jsonify(users)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/bans')
@admin_required
def get_bans():
    """Get all banned users with details"""
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        # Get bans with user info
        if db_type == 'postgres':
            c.execute("""
                SELECT b.id, b.user_id, b.reason, b.banned_by, b.banned_at, b.expires_at,
                       u.name, u.email
                FROM bans b
                JOIN users u ON b.user_id = u.id
                ORDER BY b.banned_at DESC
            """)
        else:
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
            except:
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
            bans.append(ban)
        return jsonify(bans)
    except Exception as e:
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
    
    # Get target user's current role
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        else:
            c.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        try:
            current_role = row["role"] or "user"
        except:
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
        if db_type == 'postgres':
            c.execute("UPDATE users SET role = %s, is_admin = %s WHERE id = %s", 
                     (new_role, is_admin, user_id))
        else:
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
    reason = data.get('reason', '')
    
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        # Get target user
        if db_type == 'postgres':
            c.execute("SELECT role, is_admin FROM users WHERE id = %s", (user_id,))
        else:
            c.execute("SELECT role, is_admin FROM users WHERE id = ?", (user_id,))
        
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        try:
            target_role = row["role"] or "user"
        except:
            target_role = row[0] or "user"
        
        # Cannot ban higher or equal roles
        if not can_modify_role(admin['role'], target_role):
            conn.close()
            return jsonify({"error": "Cannot ban this user"}), 403
        
        # Update ban status
        if db_type == 'postgres':
            c.execute("UPDATE users SET is_banned = %s WHERE id = %s", 
                     (1 if banned else 0, user_id))
        else:
            c.execute("UPDATE users SET is_banned = ? WHERE id = ?", 
                     (1 if banned else 0, user_id))
        
        # Add/remove from bans table
        if banned:
            if db_type == 'postgres':
                c.execute("""
                    INSERT INTO bans (user_id, reason, banned_by, banned_at, expires_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (user_id) DO UPDATE SET
                    reason = EXCLUDED.reason, banned_by = EXCLUDED.banned_by, banned_at = EXCLUDED.banned_at
                """, (user_id, reason, admin['role'], datetime.now(), None))
            else:
                c.execute("""
                    INSERT OR REPLACE INTO bans (user_id, reason, banned_by, banned_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (user_id, reason, admin['role'], datetime.now(), None))
        else:
            if db_type == 'postgres':
                c.execute("DELETE FROM bans WHERE user_id = %s", (user_id,))
            else:
                c.execute("DELETE FROM bans WHERE user_id = ?", (user_id,))
        
        conn.commit()
        conn.close()
        
        log_action("BAN" if banned else "UNBAN", f"User {user_id}: {reason}")
        return jsonify({"success": True})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/audit-logs')
@admin_required
def get_audit_logs():
    """Get audit logs"""
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        c.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100")
        rows = c.fetchall()
        conn.close()
        
        logs = []
        for row in rows:
            try:
                log = {
                    "id": row["id"],
                    "admin_id": row["admin_id"],
                    "action": row["action"],
                    "details": row["details"],
                    "ip_address": row["ip_address"],
                    "timestamp": row["timestamp"]
                }
            except:
                log = {
                    "id": row[0],
                    "admin_id": row[1],
                    "action": row[2],
                    "details": row[3],
                    "ip_address": row[4],
                    "timestamp": row[5]
                }
            logs.append(log)
        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/settings', methods=['GET', 'POST'])
@admin_required
def settings():
    """Get/update settings"""
    admin = get_admin_session()
    
    # Only owners can change settings
    if admin['role'] != 'owner':
        return jsonify({"error": "Owner access required"}), 403
    
    if request.method == 'GET':
        return jsonify({
            "site_name": os.environ.get('SITE_NAME', 'AI.Bible'),
            "maintenance_mode": os.environ.get('MAINTENANCE_MODE', 'false'),
            "codes": ROLE_CODES
        })
    
    # POST - update settings
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
