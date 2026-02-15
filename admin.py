"""
Admin Panel - Fixed with ban durations, comment management, mobile responsive
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

def get_db():
    from app import get_db as app_get_db
    return app_get_db()

def get_admin_session():
    if 'admin_role' not in session:
        return None
    return {'role': session.get('admin_role'), 'level': ROLE_HIERARCHY.get(session.get('admin_role'), 0)}

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

@admin_bp.route('/api/comments')
@admin_required
def get_comments():
    """Get all comments for moderation"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Ensure comments table has necessary columns
        try:
            c.execute("SELECT is_deleted FROM comments LIMIT 1")
        except:
            c.execute("ALTER TABLE comments ADD COLUMN is_deleted INTEGER DEFAULT 0")
            conn.commit()
        
        c.execute("""
            SELECT c.id, c.verse_id, c.text, c.timestamp, c.google_name, u.name as user_name, u.email
            FROM comments c
            LEFT JOIN users u ON c.user_id = u.id
            WHERE c.is_deleted = 0 OR c.is_deleted IS NULL
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
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/api/comments/<int:comment_id>', methods=['DELETE'])
@admin_required
def delete_comment(comment_id):
    """Soft delete a comment"""
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Soft delete
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
def ban_user(user_id):
    admin = get_admin_session()
    data = request.get_json()
    banned = data.get('banned', True)
    reason = data.get('reason', 'No reason provided')
    duration = data.get('duration', 'permanent')  # Format: "30m", "2h", "1d", "1w", "1mo", "permanent"
    
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
            # Calculate expiration
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
def get_settings():
    admin = get_admin_session()
    
    return jsonify({
        "site_name": os.environ.get('SITE_NAME', 'AI.Bible'),
        "maintenance_mode": os.environ.get('MAINTENANCE_MODE', 'false'),
        "codes": ROLE_CODES,
        "role": admin['role'],
        "is_owner": admin['role'] == 'owner'
    })

@admin_bp.route('/api/check-session')
def check_session():
    admin = get_admin_session()
    if admin:
        return jsonify({"logged_in": True, "role": admin['role']})
    return jsonify({"logged_in": False}), 401
