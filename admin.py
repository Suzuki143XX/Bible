"""
Admin Panel Module for Bible AI
Provides comprehensive admin functionality for managing users, audits, and system settings.
"""

from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for, flash
from functools import wraps
from datetime import datetime, timedelta
import json
import logging

logger = logging.getLogger(__name__)

# Create admin blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def get_db():
    """Import from main app to avoid circular imports"""
    from app import get_db as app_get_db
    return app_get_db()

def get_cursor(conn, db_type):
    """Import from main app"""
    from app import get_cursor as app_get_cursor
    return app_get_cursor(conn, db_type)

def log_action(admin_id, action, target_user_id=None, details=None):
    """Import from main app"""
    from app import log_action as app_log_action
    app_log_action(admin_id, action, target_user_id, details)

def check_ban_status(user_id):
    """Import from main app"""
    from app import check_ban_status as app_check_ban_status
    return app_check_ban_status(user_id)

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('admin.admin_login'))
        if not session.get('is_admin'):
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# Routes
@admin_bp.route('/')
@admin_required
def admin_index():
    """Redirect to dashboard"""
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/login')
def admin_login():
    """Admin login page"""
    if 'user_id' in session and session.get('is_admin'):
        return redirect(url_for('admin.admin_dashboard'))
    return render_template('admin_login.html')

@admin_bp.route('/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    stats = {}
    try:
        # User stats
        if db_type == 'postgres':
            c.execute("SELECT COUNT(*) as count FROM users")
            stats['total_users'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM users WHERE is_admin = 1")
            stats['admin_users'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM users WHERE is_banned = TRUE")
            stats['banned_users'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM users WHERE created_at > %s", 
                     ((datetime.now() - timedelta(days=7)).isoformat(),))
            stats['new_users_week'] = c.fetchone()['count']
        else:
            c.execute("SELECT COUNT(*) as count FROM users")
            stats['total_users'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) as count FROM users WHERE is_admin = 1")
            stats['admin_users'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) as count FROM users WHERE is_banned = 1")
            stats['banned_users'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) as count FROM users WHERE created_at > ?", 
                     ((datetime.now() - timedelta(days=7)).isoformat(),))
            stats['new_users_week'] = c.fetchone()[0]
        
        # Content stats
        if db_type == 'postgres':
            c.execute("SELECT COUNT(*) as count FROM verses")
            stats['total_verses'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM likes")
            stats['total_likes'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM saves")
            stats['total_saves'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM comments")
            stats['total_comments'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM community_messages")
            stats['total_community'] = c.fetchone()['count']
        else:
            c.execute("SELECT COUNT(*) as count FROM verses")
            stats['total_verses'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) as count FROM likes")
            stats['total_likes'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) as count FROM saves")
            stats['total_saves'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) as count FROM comments")
            stats['total_comments'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) as count FROM community_messages")
            stats['total_community'] = c.fetchone()[0]
        
        # Recent activity
        if db_type == 'postgres':
            c.execute("""
                SELECT a.*, u1.name as admin_name, u2.name as target_name 
                FROM audit_logs a 
                LEFT JOIN users u1 ON a.admin_id = u1.id 
                LEFT JOIN users u2 ON a.target_user_id = u2.id 
                ORDER BY a.created_at DESC 
                LIMIT 10
            """)
        else:
            c.execute("""
                SELECT a.*, u1.name as admin_name, u2.name as target_name 
                FROM audit_logs a 
                LEFT JOIN users u1 ON a.admin_id = u1.id 
                LEFT JOIN users u2 ON a.target_user_id = u2.id 
                ORDER BY a.created_at DESC 
                LIMIT 10
            """)
        
        recent_activity = []
        for row in c.fetchall():
            if isinstance(row, dict):
                recent_activity.append({
                    'id': row['id'],
                    'admin_name': row['admin_name'] or 'System',
                    'action': row['action'],
                    'target_name': row['target_name'],
                    'details': row['details'],
                    'created_at': row['created_at']
                })
            else:
                recent_activity.append({
                    'id': row[0],
                    'admin_name': row[5] or 'System',
                    'action': row[2],
                    'target_name': row[6],
                    'details': row[4],
                    'created_at': row[5]
                })
        
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        stats = {}
        recent_activity = []
    finally:
        conn.close()
    
    return render_template('admin_dashboard.html', stats=stats, recent_activity=recent_activity)

@admin_bp.route('/users')
@admin_required
def admin_users():
    """Users management page"""
    return render_template('admin_users.html')

@admin_bp.route('/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    """User detail page"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        else:
            c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        
        user = c.fetchone()
        if not user:
            return "User not found", 404
        
        if isinstance(user, dict):
            user_data = {
                'id': user['id'],
                'google_id': user['google_id'],
                'email': user['email'],
                'name': user['name'],
                'picture': user['picture'],
                'created_at': user['created_at'],
                'is_admin': bool(user['is_admin']),
                'is_banned': bool(user['is_banned']),
                'ban_expires_at': user['ban_expires_at'],
                'ban_reason': user['ban_reason'],
                'role': user['role'] or 'user'
            }
        else:
            user_data = {
                'id': user[0],
                'google_id': user[1],
                'email': user[2],
                'name': user[3],
                'picture': user[4],
                'created_at': user[5],
                'is_admin': bool(user[6]),
                'is_banned': bool(user[7]),
                'ban_expires_at': user[8],
                'ban_reason': user[9],
                'role': user[10] if len(user) > 10 else 'user'
            }
        
        # Get user stats
        if db_type == 'postgres':
            c.execute("SELECT COUNT(*) FROM likes WHERE user_id = %s", (user_id,))
            user_data['likes_count'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) FROM saves WHERE user_id = %s", (user_id,))
            user_data['saves_count'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) FROM comments WHERE user_id = %s", (user_id,))
            user_data['comments_count'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) FROM community_messages WHERE user_id = %s", (user_id,))
            user_data['messages_count'] = c.fetchone()['count']
        else:
            c.execute("SELECT COUNT(*) FROM likes WHERE user_id = ?", (user_id,))
            user_data['likes_count'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM saves WHERE user_id = ?", (user_id,))
            user_data['saves_count'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM comments WHERE user_id = ?", (user_id,))
            user_data['comments_count'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM community_messages WHERE user_id = ?", (user_id,))
            user_data['messages_count'] = c.fetchone()[0]
        
        # Get recent audit logs for this user
        if db_type == 'postgres':
            c.execute("""
                SELECT a.*, u1.name as admin_name 
                FROM audit_logs a 
                LEFT JOIN users u1 ON a.admin_id = u1.id 
                WHERE a.target_user_id = %s
                ORDER BY a.created_at DESC 
                LIMIT 20
            """, (user_id,))
        else:
            c.execute("""
                SELECT a.*, u1.name as admin_name 
                FROM audit_logs a 
                LEFT JOIN users u1 ON a.admin_id = u1.id 
                WHERE a.target_user_id = ?
                ORDER BY a.created_at DESC 
                LIMIT 20
            """, (user_id,))
        
        user_logs = []
        for row in c.fetchall():
            if isinstance(row, dict):
                user_logs.append({
                    'id': row['id'],
                    'admin_name': row['admin_name'] or 'System',
                    'action': row['action'],
                    'details': row['details'],
                    'created_at': row['created_at']
                })
            else:
                user_logs.append({
                    'id': row[0],
                    'admin_name': row[6] or 'System',
                    'action': row[2],
                    'details': row[4],
                    'created_at': row[5]
                })
        
    except Exception as e:
        logger.error(f"User detail error: {e}")
        return f"Error: {e}", 500
    finally:
        conn.close()
    
    return render_template('admin_user_detail.html', user=user_data, logs=user_logs)

@admin_bp.route('/audits')
@admin_required
def admin_audits():
    """Audit logs page"""
    return render_template('admin_audits.html')

@admin_bp.route('/settings')
@admin_required
def admin_settings():
    """Admin settings page"""
    return render_template('admin_settings.html')

# API Endpoints
@admin_bp.route('/api/stats')
@admin_required
def api_stats():
    """Get admin dashboard stats"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        stats = {}
        
        if db_type == 'postgres':
            c.execute("SELECT COUNT(*) as count FROM users")
            stats['total_users'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM users WHERE is_admin = 1")
            stats['admin_users'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM users WHERE is_banned = TRUE")
            stats['banned_users'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM verses")
            stats['total_verses'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM likes")
            stats['total_likes'] = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM comments")
            stats['total_comments'] = c.fetchone()['count']
        else:
            c.execute("SELECT COUNT(*) as count FROM users")
            stats['total_users'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) as count FROM users WHERE is_admin = 1")
            stats['admin_users'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) as count FROM users WHERE is_banned = 1")
            stats['banned_users'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) as count FROM verses")
            stats['total_verses'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) as count FROM likes")
            stats['total_likes'] = c.fetchone()[0]
            c.execute("SELECT COUNT(*) as count FROM comments")
            stats['total_comments'] = c.fetchone()[0]
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"API stats error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@admin_bp.route('/api/users')
@admin_required
def api_users():
    """Get users list with filtering and pagination"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    role = request.args.get('role', 'all')
    status = request.args.get('status', 'all')
    sort_by = request.args.get('sort_by', 'created_at')
    sort_order = request.args.get('sort_order', 'desc')
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        # Build query
        where_clauses = []
        params = []
        
        if search:
            where_clauses.append("(name ILIKE %s OR email ILIKE %s)" if db_type == 'postgres' else "(name LIKE ? OR email LIKE ?)")
            params.extend([f'%{search}%', f'%{search}%'])
        
        if role != 'all':
            where_clauses.append("role = %s" if db_type == 'postgres' else "role = ?")
            params.append(role)
        
        if status == 'banned':
            where_clauses.append("is_banned = %s" if db_type == 'postgres' else "is_banned = ?")
            params.append(True if db_type == 'postgres' else 1)
        elif status == 'active':
            where_clauses.append("is_banned = %s" if db_type == 'postgres' else "is_banned = ?")
            params.append(False if db_type == 'postgres' else 0)
        elif status == 'admin':
            where_clauses.append("is_admin = %s" if db_type == 'postgres' else "is_admin = ?")
            params.append(True if db_type == 'postgres' else 1)
        
        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        # Get total count
        count_sql = f"SELECT COUNT(*) as count FROM users {where_sql}"
        c.execute(count_sql, params)
        total = c.fetchone()['count'] if isinstance(c.fetchone(), dict) else c.fetchone()[0]
        
        # Get users
        order_sql = f"ORDER BY {sort_by} {'DESC' if sort_order == 'desc' else 'ASC'}"
        limit_sql = "LIMIT %s OFFSET %s" if db_type == 'postgres' else "LIMIT ? OFFSET ?"
        
        sql = f"SELECT * FROM users {where_sql} {order_sql} {limit_sql}"
        offset = (page - 1) * per_page
        query_params = params + [per_page, offset]
        
        c.execute(sql, query_params)
        
        users = []
        for row in c.fetchall():
            if isinstance(row, dict):
                users.append({
                    'id': row['id'],
                    'email': row['email'],
                    'name': row['name'],
                    'picture': row['picture'],
                    'created_at': row['created_at'],
                    'is_admin': bool(row['is_admin']),
                    'is_banned': bool(row['is_banned']),
                    'role': row['role'] or 'user'
                })
            else:
                users.append({
                    'id': row[0],
                    'email': row[2],
                    'name': row[3],
                    'picture': row[4],
                    'created_at': row[5],
                    'is_admin': bool(row[6]),
                    'is_banned': bool(row[7]),
                    'role': row[10] if len(row) > 10 else 'user'
                })
        
        return jsonify({
            'users': users,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        })
    except Exception as e:
        logger.error(f"API users error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@admin_bp.route('/api/user/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def api_user(user_id):
    """Get, update or delete a user"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if request.method == 'GET':
            if db_type == 'postgres':
                c.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            else:
                c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            
            user = c.fetchone()
            if not user:
                return jsonify({"error": "User not found"}), 404
            
            if isinstance(user, dict):
                user_data = {
                    'id': user['id'],
                    'email': user['email'],
                    'name': user['name'],
                    'picture': user['picture'],
                    'created_at': user['created_at'],
                    'is_admin': bool(user['is_admin']),
                    'is_banned': bool(user['is_banned']),
                    'ban_expires_at': user['ban_expires_at'],
                    'ban_reason': user['ban_reason'],
                    'role': user['role'] or 'user'
                }
            else:
                user_data = {
                    'id': user[0],
                    'email': user[2],
                    'name': user[3],
                    'picture': user[4],
                    'created_at': user[5],
                    'is_admin': bool(user[6]),
                    'is_banned': bool(user[7]),
                    'ban_expires_at': user[8],
                    'ban_reason': user[9],
                    'role': user[10] if len(user) > 10 else 'user'
                }
            
            return jsonify(user_data)
        
        elif request.method == 'PUT':
            data = request.get_json()
            updates = []
            params = []
            
            if 'role' in data:
                updates.append("role = %s" if db_type == 'postgres' else "role = ?")
                params.append(data['role'])
                
                # Update is_admin based on role
                is_admin = 1 if data['role'] in ['admin', 'host', 'superadmin'] else 0
                updates.append("is_admin = %s" if db_type == 'postgres' else "is_admin = ?")
                params.append(is_admin)
            
            if 'is_banned' in data:
                updates.append("is_banned = %s" if db_type == 'postgres' else "is_banned = ?")
                params.append(data['is_banned'])
            
            if 'ban_reason' in data:
                updates.append("ban_reason = %s" if db_type == 'postgres' else "ban_reason = ?")
                params.append(data['ban_reason'])
            
            if 'ban_expires_at' in data:
                updates.append("ban_expires_at = %s" if db_type == 'postgres' else "ban_expires_at = ?")
                params.append(data['ban_expires_at'])
            
            if not updates:
                return jsonify({"error": "No updates provided"}), 400
            
            params.append(user_id)
            sql = f"UPDATE users SET {', '.join(updates)} WHERE id = %s" if db_type == 'postgres' else f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
            c.execute(sql, params)
            conn.commit()
            
            # Log the action
            log_action(session['user_id'], 'user_updated', user_id, data)
            
            return jsonify({"success": True})
        
        elif request.method == 'DELETE':
            # Soft delete - ban the user permanently
            if db_type == 'postgres':
                c.execute("UPDATE users SET is_banned = TRUE, ban_reason = 'Account deleted by admin' WHERE id = %s", (user_id,))
            else:
                c.execute("UPDATE users SET is_banned = 1, ban_reason = 'Account deleted by admin' WHERE id = ?", (user_id,))
            conn.commit()
            
            log_action(session['user_id'], 'user_deleted', user_id)
            
            return jsonify({"success": True})
    
    except Exception as e:
        logger.error(f"API user error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@admin_bp.route('/api/user/<int:user_id>/ban', methods=['POST'])
@admin_required
def api_ban_user(user_id):
    """Ban a user"""
    data = request.get_json()
    reason = data.get('reason', 'Violation of terms')
    duration = data.get('duration')  # In hours, None for permanent
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if duration:
            expires_at = (datetime.now() + timedelta(hours=int(duration))).isoformat()
        else:
            expires_at = None
        
        if db_type == 'postgres':
            c.execute("""
                UPDATE users SET is_banned = TRUE, ban_reason = %s, ban_expires_at = %s 
                WHERE id = %s
            """, (reason, expires_at, user_id))
        else:
            c.execute("""
                UPDATE users SET is_banned = 1, ban_reason = ?, ban_expires_at = ? 
                WHERE id = ?
            """, (reason, expires_at, user_id))
        
        conn.commit()
        
        log_action(session['user_id'], 'user_banned', user_id, {
            'reason': reason,
            'duration': duration,
            'expires_at': expires_at
        })
        
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Ban user error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@admin_bp.route('/api/user/<int:user_id>/unban', methods=['POST'])
@admin_required
def api_unban_user(user_id):
    """Unban a user"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("""
                UPDATE users SET is_banned = FALSE, ban_reason = NULL, ban_expires_at = NULL 
                WHERE id = %s
            """, (user_id,))
        else:
            c.execute("""
                UPDATE users SET is_banned = 0, ban_reason = NULL, ban_expires_at = NULL 
                WHERE id = ?
            """, (user_id,))
        
        conn.commit()
        
        log_action(session['user_id'], 'user_unbanned', user_id)
        
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Unban user error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@admin_bp.route('/api/audits')
@admin_required
def api_audits():
    """Get audit logs with filtering and pagination"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    action = request.args.get('action', 'all')
    admin_id = request.args.get('admin_id', type=int)
    user_id = request.args.get('user_id', type=int)
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        where_clauses = []
        params = []
        
        if action != 'all':
            where_clauses.append("action = %s" if db_type == 'postgres' else "action = ?")
            params.append(action)
        
        if admin_id:
            where_clauses.append("admin_id = %s" if db_type == 'postgres' else "admin_id = ?")
            params.append(admin_id)
        
        if user_id:
            where_clauses.append("target_user_id = %s" if db_type == 'postgres' else "target_user_id = ?")
            params.append(user_id)
        
        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        # Get total count
        count_sql = f"SELECT COUNT(*) as count FROM audit_logs {where_sql}"
        c.execute(count_sql, params)
        total_row = c.fetchone()
        total = total_row['count'] if isinstance(total_row, dict) else total_row[0]
        
        # Get logs
        sql = f"""
            SELECT a.*, u1.name as admin_name, u2.name as target_name 
            FROM audit_logs a 
            LEFT JOIN users u1 ON a.admin_id = u1.id 
            LEFT JOIN users u2 ON a.target_user_id = u2.id 
            {where_sql}
            ORDER BY a.created_at DESC 
            LIMIT %s OFFSET %s
        """ if db_type == 'postgres' else f"""
            SELECT a.*, u1.name as admin_name, u2.name as target_name 
            FROM audit_logs a 
            LEFT JOIN users u1 ON a.admin_id = u1.id 
            LEFT JOIN users u2 ON a.target_user_id = u2.id 
            {where_sql}
            ORDER BY a.created_at DESC 
            LIMIT ? OFFSET ?
        """
        
        offset = (page - 1) * per_page
        c.execute(sql, params + [per_page, offset])
        
        logs = []
        for row in c.fetchall():
            if isinstance(row, dict):
                logs.append({
                    'id': row['id'],
                    'admin_id': row['admin_id'],
                    'admin_name': row['admin_name'] or 'System',
                    'action': row['action'],
                    'target_user_id': row['target_user_id'],
                    'target_name': row['target_name'],
                    'details': row['details'],
                    'created_at': row['created_at'].isoformat() if hasattr(row['created_at'], 'isoformat') else row['created_at']
                })
            else:
                logs.append({
                    'id': row[0],
                    'admin_id': row[1],
                    'admin_name': row[6] or 'System',
                    'action': row[2],
                    'target_user_id': row[3],
                    'target_name': row[7],
                    'details': row[4],
                    'created_at': row[5]
                })
        
        return jsonify({
            'logs': logs,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        })
    except Exception as e:
        logger.error(f"API audits error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@admin_bp.route('/api/system/settings', methods=['GET', 'PUT'])
@admin_required
def api_system_settings():
    """Get or update system settings"""
    if request.method == 'GET':
        # Return current system settings
        from app import ADMIN_CODE, generator
        return jsonify({
            'verse_interval': generator.interval,
            'admin_code': '********'  # Don't expose actual code
        })
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        if 'verse_interval' in data:
            from app import generator
            generator.set_interval(data['verse_interval'])
            log_action(session['user_id'], 'system_settings_updated', details={
                'verse_interval': data['verse_interval']
            })
        
        return jsonify({"success": True})

@admin_bp.route('/api/user/<int:user_id>/activity')
@admin_required
def api_user_activity(user_id):
    """Get detailed activity for a user"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        activity = {
            'likes': [],
            'saves': [],
            'comments': [],
            'messages': []
        }
        
        # Get likes
        if db_type == 'postgres':
            c.execute("""
                SELECT v.reference, v.text, l.timestamp 
                FROM likes l 
                JOIN verses v ON l.verse_id = v.id 
                WHERE l.user_id = %s 
                ORDER BY l.timestamp DESC 
                LIMIT 20
            """, (user_id,))
        else:
            c.execute("""
                SELECT v.reference, v.text, l.timestamp 
                FROM likes l 
                JOIN verses v ON l.verse_id = v.id 
                WHERE l.user_id = ? 
                ORDER BY l.timestamp DESC 
                LIMIT 20
            """, (user_id,))
        
        for row in c.fetchall():
            if isinstance(row, dict):
                activity['likes'].append({
                    'reference': row['reference'],
                    'text': row['text'][:100] + '...' if len(row['text']) > 100 else row['text'],
                    'timestamp': row['timestamp']
                })
            else:
                activity['likes'].append({
                    'reference': row[0],
                    'text': row[1][:100] + '...' if len(row[1]) > 100 else row[1],
                    'timestamp': row[2]
                })
        
        # Get saves
        if db_type == 'postgres':
            c.execute("""
                SELECT v.reference, v.text, s.timestamp 
                FROM saves s 
                JOIN verses v ON s.verse_id = v.id 
                WHERE s.user_id = %s 
                ORDER BY s.timestamp DESC 
                LIMIT 20
            """, (user_id,))
        else:
            c.execute("""
                SELECT v.reference, v.text, s.timestamp 
                FROM saves s 
                JOIN verses v ON s.verse_id = v.id 
                WHERE s.user_id = ? 
                ORDER BY s.timestamp DESC 
                LIMIT 20
            """, (user_id,))
        
        for row in c.fetchall():
            if isinstance(row, dict):
                activity['saves'].append({
                    'reference': row['reference'],
                    'text': row['text'][:100] + '...' if len(row['text']) > 100 else row['text'],
                    'timestamp': row['timestamp']
                })
            else:
                activity['saves'].append({
                    'reference': row[0],
                    'text': row[1][:100] + '...' if len(row[1]) > 100 else row[1],
                    'timestamp': row[2]
                })
        
        return jsonify(activity)
    except Exception as e:
        logger.error(f"User activity error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()
