"""
Admin Panel - Role-based permissions with comment restrictions
"""
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, current_app
from functools import wraps
from datetime import datetime, timedelta
import os
import sqlite3

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

ROLE_HIERARCHY = {'user': 0, 'host': 1, 'mod': 2, 'co_owner': 3, 'owner': 4}

ROLE_CODES = {
    'host': os.environ.get('HOST_CODE', 'HOST123'),
    'mod': os.environ.get('MOD_CODE', 'MOD456'),
    'co_owner': os.environ.get('CO_OWNER_CODE', 'COOWNER789'),
    'owner': os.environ.get('OWNER_CODE', 'OWNER999')
}

# Permissions by role
ROLE_PERMISSIONS = {
    'host': ['ban', 'timeout', 'restrict_comments', 'view_users', 'view_bans', 'view_audit'],
    'mod': ['ban', 'timeout', 'restrict_comments', 'view_users', 'view_bans', 'view_audit', 'delete_comments'],
    'co_owner': ['ban', 'timeout', 'restrict_comments', 'view_users', 'view_bans', 'view_audit', 'delete_comments', 
                 'change_roles', 'view_settings'],
    'owner': ['ban', 'timeout', 'restrict_comments', 'view_users', 'view_bans', 'view_audit', 'delete_comments',
              'change_roles', 'view_settings', 'edit_settings', 'full_access']
}

def get_db():
    from app import get_db as app_get_db
    return app_get_db()

def get_admin_session():
    if 'admin_role' not in session:
        return None
    return {'role': session.get('admin_role'), 'level': ROLE_HIERARCHY.get(session.get('admin_role'), 0)}

def has_permission(permission):
    """Check if current admin has specific permission"""
    admin = get_admin_session()
    if not admin:
        return False
    return permission in ROLE_PERMISSIONS.get(admin['role'], [])

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin = get_admin_session()
        if not admin:
            if request.is_json:
                return jsonify({"error": "Admin login required"}), 401
            return redirect(url_for('admin.admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def require_permission(permission):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_permission(permission):
                return jsonify({"error": "Permission denied"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def can_modify_role(admin_role, target_role):
    return ROLE_HIERARCHY.get(admin_role, 0) > ROLE_HIERARCHY.get(target_role, 0)

def log_action(action, details=""):
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        admin = get_admin_session()
        admin_id = admin['role'] if admin else 'unknown'
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        c.execute("INSERT INTO audit_logs (admin_id, action, details, ip_address, timestamp) VALUES (?, ?, ?, ?, ?)",
                 (admin_id, action, details, request.remote_addr, timestamp))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Log action failed: {e}")

@admin_bp.route('/login')
def admin_login():
    if get_admin_session():
        return redirect(url_for('admin.admin_dashboard'))
    return render_template('admin_login_simple.html')

@admin_bp.route('/dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@admin_bp.route('/logout', methods=['POST'])
def admin_logout():
    session.pop('admin_role', None)
    session.pop('admin_code', None)
    return redirect(url_for('admin.admin_login'))

@admin_bp.route('/api/verify-code', methods=['POST'])
def verify_code():
    data = request.get_json()
    code = data.get('code', '').strip()
    
    if not code:
        return jsonify({"success": False, "error": "Code required"}), 400
    
    for role, role_code in ROLE_CODES.items():
        if code == role_code:
            session['admin_role'] = role
            session['admin_code'] = code
            log_action("ADMIN_LOGIN", f"Role: {role}")
            return jsonify({"success": True, "role": role, "redirect": "/admin/dashboard"})
    
    return jsonify({"success": False, "error": "Invalid code"}), 401

@admin_bp.route('/api/permissions')
@admin_required
def get_permissions():
    """Get current admin permissions"""
    admin = get_admin_session()
    return jsonify({
        "role": admin['role'],
        "permissions": ROLE_PERMISSIONS.get(admin['role'], []),
        "can_access_settings": has_permission('edit_settings')
    })

@admin_bp.route('/api/stats')
@admin_required
def get_stats():
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM users")
        users = c.fetchone()[0] or 0
        
        c.execute("SELECT COUNT(*) FROM bans")
        bans = c.fetchone()[0] or 0
        
        c.execute("SELECT COUNT(*) FROM users WHERE is_banned = 1")
        banned_users = c.fetchone()[0] or 0
        
        try:
            c.execute("SELECT COUNT(*) FROM comment_restrictions WHERE expires_at > ?", (datetime.now().isoformat(),))
            restricted = c.fetchone()[0] or 0
        except:
            restricted = 0
        
        try:
            c.execute("SELECT COALESCE(SUM(views), 0) FROM verses")
            views = c.fetchone()[0] or 0
        except:
            views = 0
        
        c.execute("SELECT COUNT(*) FROM verses")
        verses = c.fetchone()[0] or 0
        
        c.execute("SELECT COUNT(*) FROM comments")
        comments = c.fetchone()[0] or 0
        
        conn.close()
        
        admin = get_admin_session()
        return jsonify({
            "users": users,
            "bans": max(bans, banned_users),
            "restricted": restricted,
            "views": views,
            "verses": verses,
            "comments": comments,
            "role": admin['role'],
            "level": admin['level']
        })
    except Exception as e:
        print(f"[ERROR] Stats: {e}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/users')
@admin_required
def get_users():
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        c.execute("SELECT id, name, email, role, is_admin, is_banned, created_at FROM users ORDER BY id DESC")
        rows = c.fetchall()
        conn.close()
        
        users = []
        for row in rows:
            users.append({
                "id": row[0],
                "name": row[1] or "Unknown",
                "email": row[2] or "No email",
                "role": row[3] or "user",
                "is_admin": bool(row[4]),
                "is_banned": bool(row[5]),
                "created_at": row[6] or "Unknown"
            })
        return jsonify(users)
    except Exception as e:
        print(f"[ERROR] Users: {e}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/bans')
@admin_required
def get_bans():
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
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
            bans.append({
                "id": row[0],
                "user_id": row[1],
                "reason": row[2] or "No reason",
                "banned_by": row[3] or "Unknown",
                "banned_at": row[4],
                "expires_at": row[5],
                "user_name": row[6] or "Unknown",
                "user_email": row[7] or "No email"
            })
        return jsonify(bans)
    except Exception as e:
        print(f"[ERROR] Bans: {e}")
        return jsonify({"error": str(e)}), 500

# Comment Restrictions (Host+ can use)
@admin_bp.route('/api/restrictions')
@admin_required
@require_permission('restrict_comments')
def get_restrictions():
    """Get all active comment restrictions"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Ensure table exists with appropriate syntax
        if db_type == 'postgres':
            c.execute("""
                CREATE TABLE IF NOT EXISTS comment_restrictions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER UNIQUE,
                    reason TEXT,
                    restricted_by TEXT,
                    restricted_at TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)
        else:
            c.execute("""
                CREATE TABLE IF NOT EXISTS comment_restrictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER UNIQUE,
                    reason TEXT,
                    restricted_by TEXT,
                    restricted_at TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)
        
        now = datetime.now().isoformat()
        if db_type == 'postgres':
            c.execute("""
                SELECT r.id, r.user_id, r.reason, r.restricted_by, r.restricted_at, r.expires_at,
                       u.name, u.email
                FROM comment_restrictions r
                LEFT JOIN users u ON r.user_id = u.id
                WHERE r.expires_at > %s
                ORDER BY r.restricted_at DESC
            """, (now,))
        else:
            c.execute("""
                SELECT r.id, r.user_id, r.reason, r.restricted_by, r.restricted_at, r.expires_at,
                       u.name, u.email
                FROM comment_restrictions r
                LEFT JOIN users u ON r.user_id = u.id
                WHERE r.expires_at > ?
                ORDER BY r.restricted_at DESC
            """, (now,))
        
        rows = c.fetchall()
        conn.close()
        
        restrictions = []
        for row in rows:
            restrictions.append({
                "id": row[0],
                "user_id": row[1],
                "reason": row[2] or "No reason",
                "restricted_by": row[3] or "Unknown",
                "restricted_at": row[4],
                "expires_at": row[5],
                "user_name": row[6] or "Unknown",
                "user_email": row[7] or "No email"
            })
        return jsonify(restrictions)
    except Exception as e:
        print(f"[ERROR] Restrictions: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/users/<int:user_id>/restrict', methods=['POST'])
@admin_required
@require_permission('restrict_comments')
def restrict_user(user_id):
    """Restrict user from commenting"""
    data = request.get_json()
    hours = data.get('hours', 24)
    reason = data.get('reason', 'No reason provided')
    
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        admin = get_admin_session()
        
        # Get user info
        if db_type == 'postgres':
            c.execute("SELECT name, role FROM users WHERE id = %s", (user_id,))
        else:
            c.execute("SELECT name, role FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        user_name, user_role = row[0] or "Unknown", row[1] or "user"
        
        # Can't restrict higher or equal roles
        if not can_modify_role(admin['role'], user_role):
            conn.close()
            return jsonify({"error": "Cannot restrict this user"}), 403
        
        # Calculate expiration
        expires_at = datetime.now() + timedelta(hours=hours)
        
        # Create table with appropriate syntax for database type
        if db_type == 'postgres':
            c.execute("""
                CREATE TABLE IF NOT EXISTS comment_restrictions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER UNIQUE,
                    reason TEXT,
                    restricted_by TEXT,
                    restricted_at TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)
            # Use INSERT ON CONFLICT for PostgreSQL
            c.execute("""
                INSERT INTO comment_restrictions (user_id, reason, restricted_by, restricted_at, expires_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (user_id) DO UPDATE SET
                    reason = EXCLUDED.reason,
                    restricted_by = EXCLUDED.restricted_by,
                    restricted_at = EXCLUDED.restricted_at,
                    expires_at = EXCLUDED.expires_at
            """, (user_id, reason, admin['role'], datetime.now().isoformat(), expires_at.isoformat()))
        else:
            c.execute("""
                CREATE TABLE IF NOT EXISTS comment_restrictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER UNIQUE,
                    reason TEXT,
                    restricted_by TEXT,
                    restricted_at TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)
            c.execute("""
                INSERT OR REPLACE INTO comment_restrictions (user_id, reason, restricted_by, restricted_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, reason, admin['role'], datetime.now().isoformat(), expires_at.isoformat()))
        
        conn.commit()
        conn.close()
        
        log_action("RESTRICT_COMMENTS", f"Restricted {user_name} ({user_id}) for {hours}h: {reason}")
        return jsonify({"success": True, "hours": hours})
    except Exception as e:
        print(f"[ERROR] Restrict: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/users/<int:user_id>/restrict', methods=['DELETE'])
@admin_required
@require_permission('restrict_comments')
def remove_restriction(user_id):
    """Remove comment restriction from user"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        if db_type == 'postgres':
            c.execute("DELETE FROM comment_restrictions WHERE user_id = %s", (user_id,))
        else:
            c.execute("DELETE FROM comment_restrictions WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        
        log_action("UNRESTRICT", f"Removed comment restriction from user {user_id}")
        return jsonify({"success": True})
    except Exception as e:
        print(f"[ERROR] Unrestrict: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/comments')
@admin_required
@require_permission('delete_comments')
def get_comments():
    """Get all comments for moderation"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Try to add is_deleted column if it doesn't exist
        try:
            if db_type == 'postgres':
                c.execute("SELECT is_deleted FROM comments LIMIT 1")
            else:
                c.execute("SELECT is_deleted FROM comments LIMIT 1")
        except Exception as col_err:
            try:
                if db_type == 'postgres':
                    c.execute("ALTER TABLE comments ADD COLUMN is_deleted INTEGER DEFAULT 0")
                else:
                    c.execute("ALTER TABLE comments ADD COLUMN is_deleted INTEGER DEFAULT 0")
                conn.commit()
            except Exception as alter_err:
                print(f"[WARN] Could not add is_deleted column: {alter_err}")
        
        # Query comments - handle both with and without is_deleted column
        try:
            if db_type == 'postgres':
                c.execute("""
                    SELECT c.id, c.verse_id, c.text, c.timestamp, c.google_name, u.name as user_name, u.email
                    FROM comments c
                    LEFT JOIN users u ON c.user_id = u.id
                    WHERE c.is_deleted = 0 OR c.is_deleted IS NULL
                    ORDER BY c.timestamp DESC
                    LIMIT 100
                """)
            else:
                c.execute("""
                    SELECT c.id, c.verse_id, c.text, c.timestamp, c.google_name, u.name as user_name, u.email
                    FROM comments c
                    LEFT JOIN users u ON c.user_id = u.id
                    WHERE c.is_deleted = 0 OR c.is_deleted IS NULL
                    ORDER BY c.timestamp DESC
                    LIMIT 100
                """)
        except Exception as query_err:
            # Fallback if is_deleted column doesn't exist
            print(f"[WARN] Fallback query due to: {query_err}")
            if db_type == 'postgres':
                c.execute("""
                    SELECT c.id, c.verse_id, c.text, c.timestamp, c.google_name, u.name as user_name, u.email
                    FROM comments c
                    LEFT JOIN users u ON c.user_id = u.id
                    ORDER BY c.timestamp DESC
                    LIMIT 100
                """)
            else:
                c.execute("""
                    SELECT c.id, c.verse_id, c.text, c.timestamp, c.google_name, u.name as user_name, u.email
                    FROM comments c
                    LEFT JOIN users u ON c.user_id = u.id
                    ORDER BY c.timestamp DESC
                    LIMIT 100
                """)
        
        rows = c.fetchall()
        conn.close()
        
        comments = []
        for row in rows:
            comments.append({
                "id": row[0],
                "verse_id": row[1],
                "text": row[2] or "",
                "timestamp": row[3],
                "google_name": row[4] or "Anonymous",
                "user_name": row[5] or row[4] or "Anonymous",
                "email": row[6] or "No email"
            })
        return jsonify(comments)
    except Exception as e:
        print(f"[ERROR] Comments: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/comments/<int:comment_id>', methods=['DELETE'])
@admin_required
@require_permission('delete_comments')
def delete_comment(comment_id):
    """Soft delete a comment"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        c.execute("UPDATE comments SET is_deleted = 1 WHERE id = ?", (comment_id,))
        conn.commit()
        conn.close()
        
        log_action("DELETE_COMMENT", f"Deleted comment {comment_id}")
        return jsonify({"success": True})
    except Exception as e:
        print(f"[ERROR] Delete comment: {e}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/users/<int:user_id>/ban', methods=['POST'])
@admin_required
@require_permission('ban')
def ban_user(user_id):
    admin = get_admin_session()
    data = request.get_json()
    banned = data.get('banned', True)
    reason = data.get('reason', 'No reason provided')
    duration = data.get('duration', 'permanent')
    
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
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
        
        c.execute("SELECT role, name FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        target_role = row[0] or "user"
        user_name = row[1] or "Unknown"
        
        if not can_modify_role(admin['role'], target_role):
            conn.close()
            return jsonify({"error": "Cannot ban this user"}), 403
        
        if banned:
            expires_at = None
            if duration != 'permanent':
                now = datetime.now()
                if duration.endswith('m'):
                    expires_at = now + timedelta(minutes=int(duration[:-1]))
                elif duration.endswith('h'):
                    expires_at = now + timedelta(hours=int(duration[:-1]))
                elif duration.endswith('d'):
                    expires_at = now + timedelta(days=int(duration[:-1]))
                elif duration.endswith('w'):
                    expires_at = now + timedelta(weeks=int(duration[:-1]))
                elif duration.endswith('mo'):
                    expires_at = now + timedelta(days=int(duration[:-2]) * 30)
                expires_at = expires_at.isoformat() if expires_at else None
            
            c.execute("UPDATE users SET is_banned = 1 WHERE id = ?", (user_id,))
            c.execute("""
                INSERT OR REPLACE INTO bans (user_id, reason, banned_by, banned_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, reason, admin['role'], datetime.now().isoformat(), expires_at))
            
            log_action("BAN", f"Banned {user_name} ({user_id}) for {duration}: {reason}")
        else:
            c.execute("UPDATE users SET is_banned = 0 WHERE id = ?", (user_id,))
            c.execute("DELETE FROM bans WHERE user_id = ?", (user_id,))
            log_action("UNBAN", f"Unbanned {user_name} ({user_id})")
        
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "banned": banned})
    except Exception as e:
        print(f"[ERROR] Ban: {e}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/users/<int:user_id>/role', methods=['POST'])
@admin_required
@require_permission('change_roles')
def update_user_role(user_id):
    admin = get_admin_session()
    data = request.get_json()
    new_role = data.get('role')
    
    if not new_role or new_role not in ROLE_HIERARCHY:
        return jsonify({"error": "Invalid role"}), 400
    
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        c.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        current_role = row[0] or "user"
        
        if not can_modify_role(admin['role'], current_role):
            conn.close()
            return jsonify({"error": "Cannot modify this user"}), 403
        
        if not can_modify_role(admin['role'], new_role):
            conn.close()
            return jsonify({"error": "Cannot assign this role"}), 403
        
        is_admin = 1 if ROLE_HIERARCHY[new_role] > 0 else 0
        c.execute("UPDATE users SET role = ?, is_admin = ? WHERE id = ?", 
                 (new_role, is_admin, user_id))
        conn.commit()
        conn.close()
        
        log_action("UPDATE_ROLE", f"User {user_id} to {new_role}")
        return jsonify({"success": True})
    except Exception as e:
        print(f"[ERROR] Update role: {e}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/audit-logs')
@admin_required
def get_audit_logs():
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
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
        
        c.execute("SELECT id, admin_id, action, details, ip_address, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 100")
        rows = c.fetchall()
        conn.close()
        
        logs = []
        for row in rows:
            logs.append({
                "id": row[0],
                "admin_id": row[1] or "system",
                "action": row[2] or "UNKNOWN",
                "details": row[3] or "",
                "ip_address": row[4] or "",
                "timestamp": row[5]
            })
        return jsonify(logs)
    except Exception as e:
        print(f"[ERROR] Audit logs: {e}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/settings', methods=['GET'])
@admin_required
@require_permission('view_settings')
def get_settings():
    admin = get_admin_session()
    
    return jsonify({
        "site_name": os.environ.get('SITE_NAME', 'AI.Bible'),
        "maintenance_mode": os.environ.get('MAINTENANCE_MODE', 'false'),
        "codes": ROLE_CODES,
        "role": admin['role'],
        "is_owner": admin['role'] == 'owner',
        "can_edit": has_permission('edit_settings')
    })

@admin_bp.route('/api/check-session')
def check_session():
    admin = get_admin_session()
    if admin:
        return jsonify({"logged_in": True, "role": admin['role']})
    return jsonify({"logged_in": False}), 401

# System Settings API
@admin_bp.route('/api/system/settings', methods=['GET'])
@admin_required
def get_system_settings():
    """Get system settings including verse refresh interval"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Ensure settings table exists
        c.execute("""
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Get verse_interval setting, default to 60 seconds
        c.execute("SELECT value FROM system_settings WHERE key = 'verse_interval'")
        row = c.fetchone()
        conn.close()
        
        verse_interval = int(row[0]) if row else 60
        
        return jsonify({
            "verse_interval": verse_interval,
            "success": True
        })
    except Exception as e:
        print(f"[ERROR] Get system settings: {e}")
        return jsonify({"verse_interval": 60, "success": True})

@admin_bp.route('/api/system/settings', methods=['PUT'])
@admin_required
@require_permission('edit_settings')
def update_system_settings():
    """Update system settings"""
    data = request.get_json()
    
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Ensure settings table exists
        c.execute("""
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Update verse_interval if provided
        if 'verse_interval' in data:
            interval = int(data['verse_interval'])
            # Validate interval (must be between 10 and 3600 seconds)
            if interval < 10 or interval > 3600:
                conn.close()
                return jsonify({"error": "Interval must be between 10 and 3600 seconds"}), 400
            
            c.execute("""
                INSERT INTO system_settings (key, value, updated_at)
                VALUES ('verse_interval', ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
            """, (str(interval),))
            
            log_action("UPDATE_SETTINGS", f"Verse interval set to {interval} seconds")
            
            # Update the running generator's interval
            try:
                from app import generator
                generator.set_interval(interval)
                print(f"[INFO] Updated generator interval to {interval} seconds")
            except Exception as gen_err:
                print(f"[WARN] Could not update generator interval: {gen_err}")
        
        conn.commit()
        conn.close()
        
        return jsonify({"success": True})
    except Exception as e:
        print(f"[ERROR] Update system settings: {e}")
        return jsonify({"error": str(e)}), 500
