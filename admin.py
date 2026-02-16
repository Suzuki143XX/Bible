"""
Admin Panel - Role-based permissions with comment restrictions
"""
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, current_app
from functools import wraps
from datetime import datetime, timedelta
import os
import sqlite3
import re
import json

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

def _get_table_columns(c, db_type, table_name):
    """Return lowercase column names for a table."""
    cols = set()
    try:
        if db_type == 'postgres':
            c.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = %s
            """, (table_name,))
            rows = c.fetchall()
            for row in rows:
                if hasattr(row, 'keys'):
                    cols.add(str(row.get('column_name', '')).lower())
                else:
                    cols.add(str(row[0]).lower())
        else:
            c.execute(f"PRAGMA table_info({table_name})")
            rows = c.fetchall()
            for row in rows:
                cols.add(str(row[1]).lower())
    except Exception as e:
        print(f"[WARN] Could not read columns for {table_name}: {e}")
    return cols

def _ensure_audit_logs_schema(conn, c, db_type):
    """Create/migrate audit_logs so queries work across older DB schemas."""
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

    cols = _get_table_columns(c, db_type, 'audit_logs')
    required = {
        'admin_id': 'TEXT',
        'action': 'TEXT',
        'target_user_id': 'INTEGER',
        'details': 'TEXT',
        'ip_address': 'TEXT',
        'timestamp': 'TIMESTAMP' if db_type == 'postgres' else 'TEXT'
    }

    for col, col_type in required.items():
        if col in cols:
            continue
        try:
            if db_type == 'postgres':
                c.execute(f"ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS {col} {col_type}")
            else:
                c.execute(f"ALTER TABLE audit_logs ADD COLUMN {col} {col_type}")
            conn.commit()
            cols.add(col)
        except Exception as e:
            if db_type == 'postgres':
                conn.rollback()
            print(f"[WARN] Could not add audit_logs.{col}: {e}")

    # Backfill timestamp from created_at for legacy tables when available.
    if 'timestamp' in cols and 'created_at' in cols:
        try:
            c.execute("UPDATE audit_logs SET timestamp = created_at WHERE timestamp IS NULL AND created_at IS NOT NULL")
            conn.commit()
        except Exception as e:
            if db_type == 'postgres':
                conn.rollback()
            print(f"[WARN] Could not backfill audit_logs.timestamp: {e}")

def _extract_target_user_id(details):
    if not details:
        return None
    text = str(details)
    if text.startswith("{") and text.endswith("}"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                for key in ("target_user_id", "user_id", "uid", "target_id"):
                    val = obj.get(key)
                    if val is not None and str(val).strip().isdigit():
                        return int(str(val).strip())
        except Exception:
            pass
    patterns = [
        r"\((\d+)\)",               # "... (123)"
        r"\buser[_\s]*id[:=\s]+(\d+)\b",
        r"\buser\s+(\d+)\b",
        r"\bid[:=\s]+(\d+)\b"
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            try:
                return int(match.group(1))
            except Exception:
                return None
    return None

def _parse_details_fields(details):
    """Extract reason/duration/name hints from legacy text details."""
    raw = details if details is not None else ""
    text = str(raw).strip()
    parsed = {}

    if not text:
        return parsed

    # JSON details
    if text.startswith("{") and text.endswith("}"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                reason_val = (
                    obj.get("reason")
                    or obj.get("ban_reason")
                    or obj.get("restriction_reason")
                    or obj.get("message")
                )
                duration_val = obj.get("duration") or obj.get("ban_duration") or obj.get("hours")
                target_name_val = (
                    obj.get("user_name")
                    or obj.get("target_name")
                    or obj.get("name")
                    or obj.get("username")
                )
                if reason_val is not None:
                    parsed["reason"] = str(reason_val)
                if duration_val is not None:
                    parsed["duration"] = str(duration_val)
                if target_name_val is not None:
                    parsed["target_name_hint"] = str(target_name_val)
                return parsed
        except Exception:
            pass

    # "Banned Name (123) for 24h: reason..."
    m = re.search(r"\bfor\s+([^:]+):\s*(.+)$", text, flags=re.IGNORECASE)
    if m:
        parsed["duration"] = m.group(1).strip()
        parsed["reason"] = m.group(2).strip()
    else:
        # "Restricted Name (123) for 6h: reason" variant
        m2 = re.search(r"\b:\s*(.+)$", text)
        if m2:
            parsed["reason"] = m2.group(1).strip()

    # Capture target name before "(id)"
    nm = re.search(r"\b(?:Banned|Unbanned|Restricted)\s+(.+?)\s+\(\d+\)", text, flags=re.IGNORECASE)
    if nm:
        parsed["target_name_hint"] = nm.group(1).strip()

    return parsed

def _fetch_user_personas(c, db_type, user_ids):
    if not user_ids:
        return {}

    ordered_ids = sorted(set(int(uid) for uid in user_ids if uid is not None))
    if not ordered_ids:
        return {}

    placeholders = ','.join(['%s'] * len(ordered_ids)) if db_type == 'postgres' else ','.join(['?'] * len(ordered_ids))
    query = f"SELECT id, name, email, role FROM users WHERE id IN ({placeholders})"
    try:
        c.execute(query, tuple(ordered_ids))
        rows = c.fetchall()
    except Exception as e:
        print(f"[WARN] Could not load user personas: {e}")
        return {}

    personas = {}
    for row in rows:
        if hasattr(row, 'keys'):
            uid = row.get('id')
            personas[uid] = {
                "name": row.get('name') or "Unknown",
                "email": row.get('email') or "",
                "role": row.get('role') or "user"
            }
        else:
            uid = row[0]
            personas[uid] = {
                "name": row[1] or "Unknown",
                "email": row[2] or "",
                "role": row[3] or "user"
            }
    return personas

def _read_audit_logs(c, db_type, limit=100, offset=0, action=None):
    cols = _get_table_columns(c, db_type, 'audit_logs')
    if not cols:
        return [], 0

    ts_col = 'timestamp' if 'timestamp' in cols else ('created_at' if 'created_at' in cols else None)
    order_col = ts_col if ts_col else 'id'
    ts_expr = ts_col if ts_col else 'NULL'
    ip_expr = 'ip_address' if 'ip_address' in cols else 'NULL'
    target_expr = 'target_user_id' if 'target_user_id' in cols else 'NULL'

    where_sql = ""
    params = []
    if action and action.lower() != 'all':
        where_sql = "WHERE action = %s" if db_type == 'postgres' else "WHERE action = ?"
        params.append(action)

    count_query = f"SELECT COUNT(*) FROM audit_logs {where_sql}"
    c.execute(count_query, tuple(params))
    total_row = c.fetchone()
    total = (total_row[0] if not hasattr(total_row, 'keys') else list(total_row.values())[0]) if total_row else 0

    limit_ph = "%s" if db_type == 'postgres' else "?"
    offset_ph = "%s" if db_type == 'postgres' else "?"
    query = f"""
        SELECT
            id,
            admin_id,
            action,
            details,
            {ip_expr} AS ip_address,
            {ts_expr} AS event_time,
            {target_expr} AS target_user_id
        FROM audit_logs
        {where_sql}
        ORDER BY {order_col} DESC, id DESC
        LIMIT {limit_ph} OFFSET {offset_ph}
    """
    c.execute(query, tuple(params + [limit, offset]))
    rows = c.fetchall()

    base_logs = []
    user_ids = set()
    for row in rows:
        if hasattr(row, 'keys'):
            log = {
                "id": row.get('id'),
                "admin_id": row.get('admin_id') or "system",
                "action": row.get('action') or "UNKNOWN",
                "details": row.get('details') or "",
                "ip_address": row.get('ip_address') or "",
                "timestamp": row.get('event_time'),
                "target_user_id": row.get('target_user_id')
            }
        else:
            log = {
                "id": row[0],
                "admin_id": row[1] or "system",
                "action": row[2] or "UNKNOWN",
                "details": row[3] or "",
                "ip_address": row[4] or "",
                "timestamp": row[5],
                "target_user_id": row[6]
            }

        if log["target_user_id"] is None:
            log["target_user_id"] = _extract_target_user_id(log["details"])
        if log["target_user_id"] is not None:
            user_ids.add(log["target_user_id"])
        base_logs.append(log)

    personas = _fetch_user_personas(c, db_type, user_ids)
    logs = []
    for log in base_logs:
        persona = personas.get(log["target_user_id"])
        parsed_details = _parse_details_fields(log["details"])
        target_name = persona["name"] if persona else (parsed_details.get("target_name_hint") or "")
        logs.append({
            "id": log["id"],
            "admin_id": log["admin_id"],
            "admin_name": log["admin_id"],
            "action": log["action"],
            "details": log["details"],
            "ip_address": log["ip_address"],
            "timestamp": log["timestamp"],
            "created_at": log["timestamp"],  # compatibility for existing audit UI
            "target_user_id": log["target_user_id"],
            "target_name": target_name,
            "target_email": persona["email"] if persona else "",
            "target_role": persona["role"] if persona else "",
            "target_persona": persona if persona else None,
            "reason": parsed_details.get("reason", ""),
            "duration": parsed_details.get("duration", "")
        })

    return logs, total

def log_action(action, details="", target_user_id=None):
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        _ensure_audit_logs_schema(conn, c, db_type)
        admin = get_admin_session()
        admin_id = admin['role'] if admin else 'unknown'
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if db_type == 'postgres':
            c.execute("""
                INSERT INTO audit_logs (admin_id, action, details, ip_address, timestamp, target_user_id)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (admin_id, action, details, request.remote_addr, timestamp, target_user_id))
        else:
            c.execute("""
                INSERT INTO audit_logs (admin_id, action, details, ip_address, timestamp, target_user_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (admin_id, action, details, request.remote_addr, timestamp, target_user_id))
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

@admin_bp.route('/audits')
@admin_required
@require_permission('view_audit')
def admin_audits():
    return render_template('admin_audits.html')

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
        replies = get_count("SELECT COUNT(*) as count FROM comment_replies WHERE COALESCE(is_deleted, 0) = 0")
        
        # Total comments activity = verse comments + community messages + replies
        total_comments = comments + community_msgs + replies
        
        print(f"[DEBUG] Admin stats: users={users}, bans={bans}, restricted={restricted}, verses={verses}, comments={comments}, community={community_msgs}, replies={replies}, total={total_comments}")
        
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

        search = (request.args.get('q') or '').strip()
        role = (request.args.get('role') or '').strip()
        status = (request.args.get('status') or '').strip().lower()

        where = []
        params = []

        if search:
            if db_type == 'postgres':
                where.append("(COALESCE(name, '') ILIKE %s OR COALESCE(email, '') ILIKE %s)")
            else:
                where.append("(LOWER(COALESCE(name, '')) LIKE ? OR LOWER(COALESCE(email, '')) LIKE ?)")
            token = f"%{search.lower()}%"
            params.extend([token, token] if db_type != 'postgres' else [f"%{search}%", f"%{search}%"])

        if role:
            where.append("role = %s" if db_type == 'postgres' else "role = ?")
            params.append(role)

        if status == 'banned':
            where.append("is_banned = TRUE" if db_type == 'postgres' else "is_banned = 1")
        elif status == 'active':
            where.append("(is_banned IS NULL OR is_banned = FALSE)" if db_type == 'postgres' else "(is_banned IS NULL OR is_banned = 0)")

        where_sql = (" WHERE " + " AND ".join(where)) if where else ""
        query = f"SELECT id, name, email, role, is_admin, is_banned, created_at FROM users{where_sql} ORDER BY id DESC"
        c.execute(query, tuple(params))
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
        
        # Log the action BEFORE closing connection
        log_action("RESTRICT_COMMENTS", f"Restricted {user_name} ({user_id}) for {hours}h: {reason}", target_user_id=user_id)
        
        conn.close()
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
        
        log_action("UNRESTRICT", f"Removed comment restriction from user {user_id}", target_user_id=user_id)
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
        comment_type = (request.args.get('type') or 'all').strip().lower()
        
        print(f"[DEBUG] Getting comments, db_type={db_type}")
        
        all_items = []
        
        def _reaction_counts(item_type, item_id):
            result = {"heart": 0, "pray": 0, "cross": 0}
            try:
                if db_type == 'postgres':
                    c.execute("""
                        SELECT reaction, COUNT(*) AS cnt
                        FROM comment_reactions
                        WHERE item_type = %s AND item_id = %s
                        GROUP BY reaction
                    """, (item_type, item_id))
                else:
                    c.execute("""
                        SELECT reaction, COUNT(*) AS cnt
                        FROM comment_reactions
                        WHERE item_type = ? AND item_id = ?
                        GROUP BY reaction
                    """, (item_type, item_id))
                rows = c.fetchall()
                for rr in rows:
                    key = (rr.get('reaction') if hasattr(rr, 'keys') else rr[0]) or ''
                    cnt = rr.get('cnt') if hasattr(rr, 'keys') else rr[1]
                    key = str(key).lower()
                    if key in result:
                        result[key] = int(cnt or 0)
            except Exception:
                pass
            return result

        def _reply_count(item_type, item_id):
            try:
                if db_type == 'postgres':
                    c.execute("""
                        SELECT COUNT(*) AS cnt FROM comment_replies
                        WHERE parent_type = %s AND parent_id = %s AND COALESCE(is_deleted, 0) = 0
                    """, (item_type, item_id))
                else:
                    c.execute("""
                        SELECT COUNT(*) AS cnt FROM comment_replies
                        WHERE parent_type = ? AND parent_id = ? AND COALESCE(is_deleted, 0) = 0
                    """, (item_type, item_id))
                row = c.fetchone()
                return int((row.get('cnt') if hasattr(row, 'keys') else row[0]) if row else 0)
            except Exception:
                return 0

        def _replies(item_type, item_id):
            try:
                if db_type == 'postgres':
                    c.execute("""
                        SELECT text, timestamp, google_name
                        FROM comment_replies
                        WHERE parent_type = %s AND parent_id = %s AND COALESCE(is_deleted, 0) = 0
                        ORDER BY timestamp ASC
                        LIMIT 20
                    """, (item_type, item_id))
                else:
                    c.execute("""
                        SELECT text, timestamp, google_name
                        FROM comment_replies
                        WHERE parent_type = ? AND parent_id = ? AND COALESCE(is_deleted, 0) = 0
                        ORDER BY timestamp ASC
                        LIMIT 20
                    """, (item_type, item_id))
                rows = c.fetchall()
                result = []
                for rr in rows:
                    if hasattr(rr, 'keys'):
                        result.append({
                            "text": rr.get('text') or "",
                            "timestamp": rr.get('timestamp'),
                            "user_name": rr.get('google_name') or "Anonymous"
                        })
                    else:
                        result.append({
                            "text": rr[0] or "",
                            "timestamp": rr[1],
                            "user_name": rr[2] or "Anonymous"
                        })
                return result
            except Exception:
                return []

        # Get verse comments
        if comment_type in ('all', 'comment'):
            try:
                if db_type == 'postgres':
                    c.execute("""
                        SELECT id, verse_id, text, timestamp, google_name, user_id, 'comment' as type
                        FROM comments
                        WHERE COALESCE(is_deleted, 0) = 0
                        ORDER BY timestamp DESC
                        LIMIT 100
                    """)
                else:
                    c.execute("""
                        SELECT id, verse_id, text, timestamp, google_name, user_id, 'comment' as type
                        FROM comments
                        WHERE COALESCE(is_deleted, 0) = 0
                        ORDER BY timestamp DESC
                        LIMIT 100
                    """)
                
                rows = c.fetchall()
                print(f"[DEBUG] Found {len(rows)} verse comments")
                
                for row in rows:
                    row_id = row[0]
                    all_items.append({
                        "id": row_id,
                        "verse_id": row[1],
                        "text": row[2] or "",
                        "timestamp": row[3],
                        "google_name": row[4] or "Anonymous",
                        "user_name": row[4] or "Anonymous",
                        "user_id": row[5],
                        "type": row[6],
                        "email": "No email",
                        "reactions": _reaction_counts("comment", row_id),
                        "reply_count": _reply_count("comment", row_id),
                        "replies": _replies("comment", row_id)
                    })
            except Exception as e:
                print(f"[ERROR] Getting verse comments: {e}")
        
        # Get community messages
        if comment_type in ('all', 'community'):
            try:
                if db_type == 'postgres':
                    c.execute("""
                        SELECT id, NULL as verse_id, text, timestamp, google_name, user_id, 'community' as type
                        FROM community_messages
                        ORDER BY timestamp DESC
                        LIMIT 100
                    """)
                else:
                    c.execute("""
                        SELECT id, NULL as verse_id, text, timestamp, google_name, user_id, 'community' as type
                        FROM community_messages
                        ORDER BY timestamp DESC
                        LIMIT 100
                    """)
                
                rows = c.fetchall()
                print(f"[DEBUG] Found {len(rows)} community messages")
                
                for row in rows:
                    row_id = row[0]
                    all_items.append({
                        "id": row_id,
                        "verse_id": row[1],
                        "text": row[2] or "",
                        "timestamp": row[3],
                        "google_name": row[4] or "Anonymous",
                        "user_name": row[4] or "Anonymous",
                        "user_id": row[5],
                        "type": row[6],
                        "email": "No email",
                        "reactions": _reaction_counts("community", row_id),
                        "reply_count": _reply_count("community", row_id),
                        "replies": _replies("community", row_id)
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
        comment_type = (request.args.get('type') or 'comment').strip().lower()
        
        if comment_type == 'community':
            if db_type == 'postgres':
                c.execute("DELETE FROM community_messages WHERE id = %s", (comment_id,))
            else:
                c.execute("DELETE FROM community_messages WHERE id = ?", (comment_id,))
        else:
            if db_type == 'postgres':
                c.execute("UPDATE comments SET is_deleted = 1 WHERE id = %s", (comment_id,))
            else:
                c.execute("UPDATE comments SET is_deleted = 1 WHERE id = ?", (comment_id,))
        conn.commit()
        conn.close()
        
        log_action("DELETE_COMMENT", f"Deleted {comment_type} {comment_id}")
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
            
            log_action("BAN", f"Banned {user_name} ({user_id}) for {duration}: {reason}", target_user_id=user_id)
        else:
            if db_type == 'postgres':
                c.execute("UPDATE users SET is_banned = FALSE WHERE id = %s", (user_id,))
                c.execute("DELETE FROM bans WHERE user_id = %s", (user_id,))
            else:
                c.execute("UPDATE users SET is_banned = 0 WHERE id = ?", (user_id,))
                c.execute("DELETE FROM bans WHERE user_id = ?", (user_id,))
            log_action("UNBAN", f"Unbanned {user_name} ({user_id})", target_user_id=user_id)
        
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
        
        log_action("UPDATE_ROLE", f"User {user_id} to {new_role}", target_user_id=user_id)
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
        _ensure_audit_logs_schema(conn, c, db_type)
        logs, _ = _read_audit_logs(c, db_type, limit=100, offset=0, action=None)
        conn.close()
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

@admin_bp.route('/api/audits')
@admin_required
@require_permission('view_audit')
def get_audits():
    """Paginated audits API for admin audits page."""
    conn = None
    try:
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(200, max(1, int(request.args.get('per_page', 50))))
        offset = (page - 1) * per_page

        action = request.args.get('action', 'all')
        action_map = {
            'user_banned': 'BAN',
            'user_unbanned': 'UNBAN',
            'user_updated': 'UPDATE_ROLE',
            'admin_verified': 'ADMIN_LOGIN',
            'system_settings_updated': 'UPDATE_SETTINGS'
        }
        normalized_action = action_map.get(action, action)

        conn, db_type = get_db()
        c = conn.cursor()
        _ensure_audit_logs_schema(conn, c, db_type)
        logs, total = _read_audit_logs(c, db_type, limit=per_page, offset=offset, action=normalized_action)
        conn.close()

        pages = max(1, (total + per_page - 1) // per_page)
        return jsonify({
            "logs": logs,
            "page": page,
            "pages": pages,
            "per_page": per_page,
            "total": total
        })
    except Exception as e:
        print(f"[ERROR] Audits API: {e}")
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
    conn = None
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        _ensure_audit_logs_schema(conn, c, db_type)
        logs, _ = _read_audit_logs(c, db_type, limit=10, offset=0, action=None)
        conn.close()
        return jsonify(logs)
    except Exception as e:
        print(f"[ERROR] Recent activity: {e}")
        if conn:
            try:
                conn.rollback()
                conn.close()
            except:
                pass
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

        defaults = {
            "verse_interval": "60",
            "auto_refresh_seconds": "30",
            "audit_retention_days": "90",
            "safety_mode": "balanced",
            "show_user_persona": "1"
        }

        placeholders = ",".join(["%s"] * len(defaults)) if db_type == 'postgres' else ",".join(["?"] * len(defaults))
        c.execute(
            f"SELECT key, value FROM system_settings WHERE key IN ({placeholders})",
            tuple(defaults.keys())
        )
        rows = c.fetchall()
        stored = {}
        for row in rows:
            if hasattr(row, 'keys'):
                stored[str(row.get('key'))] = str(row.get('value'))
            else:
                stored[str(row[0])] = str(row[1])
        conn.close()

        merged = {**defaults, **stored}
        return jsonify({
            "verse_interval": int(merged["verse_interval"]),
            "auto_refresh_seconds": int(merged["auto_refresh_seconds"]),
            "audit_retention_days": int(merged["audit_retention_days"]),
            "safety_mode": merged["safety_mode"],
            "show_user_persona": str(merged["show_user_persona"]).lower() in ("1", "true", "yes", "on"),
            "success": True
        })
    except Exception as e:
        print(f"[ERROR] Get system settings: {e}")
        return jsonify({
            "verse_interval": 60,
            "auto_refresh_seconds": 30,
            "audit_retention_days": 90,
            "safety_mode": "balanced",
            "show_user_persona": True,
            "success": True
        })

@admin_bp.route('/api/system/settings', methods=['PUT'])
@admin_required
@require_permission('edit_settings')
def update_system_settings():
    """Update system settings"""
    data = request.get_json() or {}
    
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
        
        updates = []

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
            updates.append(f"verse_interval={interval}")
            
            # Update the running generator's interval
            try:
                from app import generator
                generator.set_interval(interval)
                print(f"[INFO] Updated generator interval to {interval} seconds")
            except Exception as gen_err:
                print(f"[WARN] Could not update generator interval: {gen_err}")

        if 'auto_refresh_seconds' in data:
            auto_refresh = int(data['auto_refresh_seconds'])
            if auto_refresh < 10 or auto_refresh > 300:
                conn.close()
                return jsonify({"error": "Auto refresh must be between 10 and 300 seconds"}), 400
            if db_type == 'postgres':
                c.execute("""
                    INSERT INTO system_settings (key, value, updated_at)
                    VALUES ('auto_refresh_seconds', %s, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
                """, (str(auto_refresh),))
            else:
                c.execute("""
                    INSERT INTO system_settings (key, value, updated_at)
                    VALUES ('auto_refresh_seconds', ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """, (str(auto_refresh),))
            updates.append(f"auto_refresh_seconds={auto_refresh}")

        if 'audit_retention_days' in data:
            retention_days = int(data['audit_retention_days'])
            if retention_days < 7 or retention_days > 365:
                conn.close()
                return jsonify({"error": "Audit retention must be between 7 and 365 days"}), 400
            if db_type == 'postgres':
                c.execute("""
                    INSERT INTO system_settings (key, value, updated_at)
                    VALUES ('audit_retention_days', %s, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
                """, (str(retention_days),))
            else:
                c.execute("""
                    INSERT INTO system_settings (key, value, updated_at)
                    VALUES ('audit_retention_days', ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """, (str(retention_days),))
            updates.append(f"audit_retention_days={retention_days}")

        if 'safety_mode' in data:
            safety_mode = str(data['safety_mode']).strip().lower()
            if safety_mode not in ('strict', 'balanced', 'relaxed'):
                conn.close()
                return jsonify({"error": "Safety mode must be strict, balanced, or relaxed"}), 400
            if db_type == 'postgres':
                c.execute("""
                    INSERT INTO system_settings (key, value, updated_at)
                    VALUES ('safety_mode', %s, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
                """, (safety_mode,))
            else:
                c.execute("""
                    INSERT INTO system_settings (key, value, updated_at)
                    VALUES ('safety_mode', ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """, (safety_mode,))
            updates.append(f"safety_mode={safety_mode}")

        if 'show_user_persona' in data:
            raw_persona = data['show_user_persona']
            if isinstance(raw_persona, str):
                show_user_persona = 1 if raw_persona.strip().lower() in ('1', 'true', 'yes', 'on') else 0
            else:
                show_user_persona = 1 if bool(raw_persona) else 0
            if db_type == 'postgres':
                c.execute("""
                    INSERT INTO system_settings (key, value, updated_at)
                    VALUES ('show_user_persona', %s, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
                """, (str(show_user_persona),))
            else:
                c.execute("""
                    INSERT INTO system_settings (key, value, updated_at)
                    VALUES ('show_user_persona', ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """, (str(show_user_persona),))
            updates.append(f"show_user_persona={show_user_persona}")

        if updates:
            log_action("UPDATE_SETTINGS", "Updated system settings: " + ", ".join(updates))

        conn.commit()
        conn.close()
        
        return jsonify({"success": True})
    except Exception as e:
        print(f"[ERROR] Update system settings: {e}")
        return jsonify({"error": str(e)}), 500
