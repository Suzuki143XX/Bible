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

def log_action(action, details="", target_user_id=None):
    """Write a moderation/admin action to audit_logs with schema safeguards."""
    conn = None
    db_type = None
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        admin = get_admin_session()
        admin_id = admin['role'] if admin else 'unknown'
        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if db_type == 'postgres':
            c.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    admin_id TEXT,
                    action TEXT,
                    target_user_id INTEGER,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            c.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS target_user_id INTEGER")
            c.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS ip_address TEXT")
            c.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'audit_logs'
                  AND column_name IN ('timestamp', 'created_at')
            """)
            cols = {row[0] for row in c.fetchall()}
        else:
            c.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    admin_id TEXT,
                    action TEXT,
                    target_user_id INTEGER,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            for col, col_type in [('target_user_id', 'INTEGER'), ('ip_address', 'TEXT')]:
                try:
                    c.execute(f"SELECT {col} FROM audit_logs LIMIT 1")
                except Exception:
                    c.execute(f"ALTER TABLE audit_logs ADD COLUMN {col} {col_type}")

            c.execute("PRAGMA table_info(audit_logs)")
            cols = {row[1] for row in c.fetchall()}

        time_col = 'timestamp' if 'timestamp' in cols else ('created_at' if 'created_at' in cols else None)

        if db_type == 'postgres':
            if time_col:
                c.execute(
                    f"INSERT INTO audit_logs (admin_id, action, target_user_id, details, ip_address, {time_col}) VALUES (%s, %s, %s, %s, %s, %s)",
                    (admin_id, action, target_user_id, details, request.remote_addr, event_time)
                )
            else:
                c.execute(
                    "INSERT INTO audit_logs (admin_id, action, target_user_id, details, ip_address) VALUES (%s, %s, %s, %s, %s)",
                    (admin_id, action, target_user_id, details, request.remote_addr)
                )
        else:
            if time_col:
                c.execute(
                    f"INSERT INTO audit_logs (admin_id, action, target_user_id, details, ip_address, {time_col}) VALUES (?, ?, ?, ?, ?, ?)",
                    (admin_id, action, target_user_id, details, request.remote_addr, event_time)
                )
            else:
                c.execute(
                    "INSERT INTO audit_logs (admin_id, action, target_user_id, details, ip_address) VALUES (?, ?, ?, ?, ?)",
                    (admin_id, action, target_user_id, details, request.remote_addr)
                )

        conn.commit()
    except Exception as e:
        print(f"[ERROR] Log action failed: {e}")
        if conn and db_type == 'postgres':
            try:
                conn.rollback()
            except Exception:
                pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

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
    conn = None
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        def get_count(query, params=None):
            """Helper to get count from query, handling both db types"""
            try:
                if params:
                    c.execute(query, params)
                else:
                    c.execute(query)
                row = c.fetchone()
                if row is None:
                    return 0
                # Handle both dict-like and tuple-like rows
                if hasattr(row, 'keys'):
                    return row.get('count', 0) or 0
                else:
                    return row[0] or 0
            except Exception as e:
                print(f"[DEBUG] Query failed: {query}, error: {e}")
                return 0
        
        # Ensure tables exist first
        try:
            if db_type == 'postgres':
                c.execute("CREATE TABLE IF NOT EXISTS bans (id SERIAL PRIMARY KEY, user_id INTEGER UNIQUE, reason TEXT, banned_by TEXT, banned_at TIMESTAMP, expires_at TIMESTAMP)")
                c.execute("CREATE TABLE IF NOT EXISTS comment_restrictions (id SERIAL PRIMARY KEY, user_id INTEGER UNIQUE, reason TEXT, restricted_by TEXT, restricted_at TIMESTAMP, expires_at TIMESTAMP)")
            else:
                c.execute("CREATE TABLE IF NOT EXISTS bans (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE, reason TEXT, banned_by TEXT, banned_at TIMESTAMP, expires_at TIMESTAMP)")
                c.execute("CREATE TABLE IF NOT EXISTS comment_restrictions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE, reason TEXT, restricted_by TEXT, restricted_at TIMESTAMP, expires_at TIMESTAMP)")
            conn.commit()
        except Exception as e:
            print(f"[DEBUG] Table creation warning: {e}")
            if db_type == 'postgres':
                conn.rollback()
        
        users = get_count("SELECT COUNT(*) as count FROM users")
        bans = get_count("SELECT COUNT(*) as count FROM bans")
        
        # PostgreSQL uses boolean, SQLite uses integer
        if db_type == 'postgres':
            banned_users = get_count("SELECT COUNT(*) as count FROM users WHERE is_banned = TRUE")
        else:
            banned_users = get_count("SELECT COUNT(*) as count FROM users WHERE is_banned = 1")
        
        restricted = 0
        try:
            if db_type == 'postgres':
                restricted = get_count("SELECT COUNT(*) as count FROM comment_restrictions WHERE expires_at > NOW()")
            else:
                restricted = get_count("SELECT COUNT(*) as count FROM comment_restrictions WHERE expires_at > datetime('now')")
        except Exception as e:
            print(f"[DEBUG] Restricted count error: {e}")
        
        verses = get_count("SELECT COUNT(*) as count FROM verses")
        comments = get_count("SELECT COUNT(*) as count FROM comments")
        community_msgs = get_count("SELECT COUNT(*) as count FROM community_messages")
        
        # Total comments = verse comments + community messages
        total_comments = comments + community_msgs
        
        print(f"[DEBUG] Admin stats: users={users}, bans={bans}, restricted={restricted}, verses={verses}, comments={comments}, community={community_msgs}, total={total_comments}")
        
        if conn:
            conn.close()
        
        admin = get_admin_session()
        return jsonify({
            "users": users,
            "bans": max(bans, banned_users),
            "restricted": restricted,
            "views": 0,  # Views column doesn't exist yet
            "verses": verses,
            "comments": total_comments,
            "role": admin['role'],
            "level": admin['level']
        })
    except Exception as e:
        print(f"[ERROR] Stats: {e}")
        import traceback
        traceback.print_exc()
        if conn:
            try:
                conn.close()
            except:
                pass
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
        
        # Create table with appropriate syntax
        if db_type == 'postgres':
            c.execute("""
                CREATE TABLE IF NOT EXISTS bans (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER UNIQUE,
                    reason TEXT,
                    banned_by TEXT,
                    banned_at TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)
        else:
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
    
    print(f"[DEBUG] restrict_user called: user_id={user_id}, hours={hours}, reason={reason}")
    
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        print(f"[DEBUG] db_type={db_type}")
        
        admin = get_admin_session()
        
        # Get user info
        if db_type == 'postgres':
            c.execute("SELECT name, role FROM users WHERE id = %s", (user_id,))
        else:
            c.execute("SELECT name, role FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if not row:
            print(f"[DEBUG] User {user_id} not found")
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        user_name, user_role = row[0] or "Unknown", row[1] or "user"
        print(f"[DEBUG] Found user: {user_name}, role: {user_role}")
        
        # Can't restrict higher or equal roles
        if not can_modify_role(admin['role'], user_role):
            conn.close()
            return jsonify({"error": "Cannot restrict this user"}), 403
        
        # Calculate expiration
        expires_at = datetime.now() + timedelta(hours=hours)
        now = datetime.now().isoformat()
        expires_iso = expires_at.isoformat()
        
        print(f"[DEBUG] Creating restriction: now={now}, expires={expires_iso}")
        
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
            """, (user_id, reason, admin['role'], now, expires_iso))
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
            """, (user_id, reason, admin['role'], now, expires_iso))
        
        conn.commit()
        
        # Verify the restriction was created
        if db_type == 'postgres':
            c.execute("SELECT user_id, reason, expires_at FROM comment_restrictions WHERE user_id = %s", (user_id,))
        else:
            c.execute("SELECT user_id, reason, expires_at FROM comment_restrictions WHERE user_id = ?", (user_id,))
        verify = c.fetchone()
        print(f"[DEBUG] Verification query result: {verify}")
        
        conn.close()
        log_action("RESTRICT_COMMENTS", f"Restricted {user_name} ({user_id}) for {hours}h: {reason}", user_id)
        print(f"[DEBUG] Restriction successful for user {user_id}")
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
        
        log_action("UNRESTRICT", f"Removed comment restriction from user {user_id}", user_id)
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
    """Get all comments and community messages for moderation"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        print(f"[DEBUG] Getting comments, db_type={db_type}")
        
        all_items = []
        
        # Get verse comments
        try:
            if db_type == 'postgres':
                c.execute("""
                    SELECT id, verse_id, text, timestamp, google_name, user_id, 'comment' as type
                    FROM comments
                    ORDER BY timestamp DESC
                    LIMIT 50
                """)
            else:
                c.execute("""
                    SELECT id, verse_id, text, timestamp, google_name, user_id, 'comment' as type
                    FROM comments
                    ORDER BY timestamp DESC
                    LIMIT 50
                """)
            
            rows = c.fetchall()
            print(f"[DEBUG] Found {len(rows)} verse comments")
            
            for row in rows:
                all_items.append({
                    "id": row[0],
                    "verse_id": row[1],
                    "text": row[2] or "",
                    "timestamp": row[3],
                    "google_name": row[4] or "Anonymous",
                    "user_name": row[4] or "Anonymous",
                    "user_id": row[5],
                    "type": row[6],
                    "email": "No email"
                })
        except Exception as e:
            print(f"[ERROR] Getting verse comments: {e}")
        
        # Get community messages
        try:
            if db_type == 'postgres':
                c.execute("""
                    SELECT id, NULL as verse_id, text, timestamp, google_name, user_id, 'community' as type
                    FROM community_messages
                    ORDER BY timestamp DESC
                    LIMIT 50
                """)
            else:
                c.execute("""
                    SELECT id, NULL as verse_id, text, timestamp, google_name, user_id, 'community' as type
                    FROM community_messages
                    ORDER BY timestamp DESC
                    LIMIT 50
                """)
            
            rows = c.fetchall()
            print(f"[DEBUG] Found {len(rows)} community messages")
            
            for row in rows:
                all_items.append({
                    "id": row[0],
                    "verse_id": row[1],
                    "text": row[2] or "",
                    "timestamp": row[3],
                    "google_name": row[4] or "Anonymous",
                    "user_name": row[4] or "Anonymous",
                    "user_id": row[5],
                    "type": row[6],
                    "email": "No email"
                })
        except Exception as e:
            print(f"[ERROR] Getting community messages: {e}")
        
        conn.close()
        
        # Sort by timestamp descending
        all_items.sort(key=lambda x: x['timestamp'] if x['timestamp'] else '', reverse=True)
        
        print(f"[DEBUG] Returning {len(all_items)} total items")
        return jsonify(all_items[:100])  # Limit to 100 total
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
        
        if db_type == 'postgres':
            c.execute("UPDATE comments SET is_deleted = 1 WHERE id = %s", (comment_id,))
        else:
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
        
        # Create table with appropriate syntax
        if db_type == 'postgres':
            c.execute("""
                CREATE TABLE IF NOT EXISTS bans (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER UNIQUE,
                    reason TEXT,
                    banned_by TEXT,
                    banned_at TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """)
        else:
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
        
        if db_type == 'postgres':
            c.execute("SELECT role, name FROM users WHERE id = %s", (user_id,))
        else:
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
            
            if db_type == 'postgres':
                c.execute("UPDATE users SET is_banned = TRUE WHERE id = %s", (user_id,))
                c.execute("""
                    INSERT INTO bans (user_id, reason, banned_by, banned_at, expires_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (user_id) DO UPDATE SET
                        reason = EXCLUDED.reason,
                        banned_by = EXCLUDED.banned_by,
                        banned_at = EXCLUDED.banned_at,
                        expires_at = EXCLUDED.expires_at
                """, (user_id, reason, admin['role'], datetime.now().isoformat(), expires_at))
            else:
                c.execute("UPDATE users SET is_banned = 1 WHERE id = ?", (user_id,))
                c.execute("""
                    INSERT OR REPLACE INTO bans (user_id, reason, banned_by, banned_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (user_id, reason, admin['role'], datetime.now().isoformat(), expires_at))
            
        else:
            if db_type == 'postgres':
                c.execute("UPDATE users SET is_banned = FALSE WHERE id = %s", (user_id,))
                c.execute("DELETE FROM bans WHERE user_id = %s", (user_id,))
            else:
                c.execute("UPDATE users SET is_banned = 0 WHERE id = ?", (user_id,))
                c.execute("DELETE FROM bans WHERE user_id = ?", (user_id,))
        
        conn.commit()
        conn.close()

        if banned:
            log_action("BAN", f"Banned {user_name} ({user_id}) for {duration}: {reason}", user_id)
        else:
            log_action("UNBAN", f"Unbanned {user_name} ({user_id})", user_id)
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
        
        if db_type == 'postgres':
            c.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        else:
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
        print(f"[ERROR] Update role: {e}")
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/audit-logs')
@admin_required
def get_audit_logs():
    conn = None
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Create table with appropriate syntax
        if db_type == 'postgres':
            c.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    admin_id TEXT,
                    action TEXT,
                    target_user_id INTEGER,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            # Add columns if they don't exist (for existing tables)
            try:
                c.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS ip_address TEXT")
                conn.commit()
            except:
                conn.rollback()
            try:
                c.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS target_user_id INTEGER")
                conn.commit()
            except:
                conn.rollback()
        else:
            c.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    admin_id TEXT,
                    action TEXT,
                    target_user_id INTEGER,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            # SQLite migrations
            for col, col_type in [('ip_address', 'TEXT'), ('target_user_id', 'INTEGER')]:
                try:
                    c.execute(f"SELECT {col} FROM audit_logs LIMIT 1")
                except:
                    try:
                        c.execute(f"ALTER TABLE audit_logs ADD COLUMN {col} {col_type}")
                        conn.commit()
                    except:
                        pass

        # Resolve timestamp column compatibility (timestamp vs created_at)
        time_col = None
        if db_type == 'postgres':
            c.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'audit_logs'
                  AND column_name IN ('timestamp', 'created_at')
            """)
            cols = {row[0] for row in c.fetchall()}
            if 'timestamp' in cols:
                time_col = 'timestamp'
            elif 'created_at' in cols:
                time_col = 'created_at'
        else:
            c.execute("PRAGMA table_info(audit_logs)")
            cols = {row[1] for row in c.fetchall()}
            if 'timestamp' in cols:
                time_col = 'timestamp'
            elif 'created_at' in cols:
                time_col = 'created_at'

        if time_col:
            c.execute(f"SELECT id, admin_id, action, details, ip_address, {time_col} as event_time FROM audit_logs ORDER BY {time_col} DESC LIMIT 100")
        else:
            c.execute("SELECT id, admin_id, action, details, ip_address, NULL as event_time FROM audit_logs ORDER BY id DESC LIMIT 100")

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
        if conn:
            try:
                conn.rollback()
                conn.close()
            except:
                pass
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/recent-activity')
@admin_required
def get_recent_activity():
    """Get recent activity for dashboard (last 10 actions)"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Ensure table exists
        if db_type == 'postgres':
            c.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    admin_id TEXT,
                    action TEXT,
                    target_user_id INTEGER,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            c.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    admin_id TEXT,
                    action TEXT,
                    target_user_id INTEGER,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        conn.commit()

        # Resolve timestamp column compatibility (timestamp vs created_at)
        time_col = None
        if db_type == 'postgres':
            c.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'audit_logs'
                  AND column_name IN ('timestamp', 'created_at')
            """)
            cols = {row[0] for row in c.fetchall()}
            if 'timestamp' in cols:
                time_col = 'timestamp'
            elif 'created_at' in cols:
                time_col = 'created_at'
        else:
            c.execute("PRAGMA table_info(audit_logs)")
            cols = {row[1] for row in c.fetchall()}
            if 'timestamp' in cols:
                time_col = 'timestamp'
            elif 'created_at' in cols:
                time_col = 'created_at'

        if time_col:
            c.execute(f"SELECT id, admin_id, action, details, {time_col} as event_time FROM audit_logs ORDER BY {time_col} DESC LIMIT 10")
        else:
            c.execute("SELECT id, admin_id, action, details, NULL as event_time FROM audit_logs ORDER BY id DESC LIMIT 10")

        rows = c.fetchall()
        conn.close()
        
        logs = []
        for row in rows:
            logs.append({
                "id": row[0],
                "admin_id": row[1] or "system",
                "action": row[2] or "UNKNOWN",
                "details": row[3] or "",
                "timestamp": row[4]
            })
        return jsonify(logs)
    except Exception as e:
        print(f"[ERROR] Recent activity: {e}")
        return jsonify([]), 200  # Return empty array on error

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
            
            if db_type == 'postgres':
                c.execute("""
                    INSERT INTO system_settings (key, value, updated_at)
                    VALUES ('verse_interval', %s, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET
                        value = EXCLUDED.value,
                        updated_at = EXCLUDED.updated_at
                """, (str(interval),))
            else:
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









