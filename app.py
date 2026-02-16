from flask import Flask, render_template, jsonify, request, redirect, url_for, session, send_from_directory, flash, render_template_string
import sqlite3
import time
import threading
import requests
import os
import re
import secrets
import json
import random
import logging
from datetime import datetime, timedelta
from functools import wraps

# Load environment variables from .env file (for local development)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, use system env vars

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.permanent_session_lifetime = timedelta(days=30)

@app.before_request
def make_session_permanent():
    session.permanent = True

# Configuration
app.secret_key = os.environ.get('SECRET_KEY', 'eK8#mP2$vL9@nQ4&wX5*fJ7!hR3(tY6)bU1$cI0~pO8+lA2=zS9')
PUBLIC_URL = os.environ.get('RENDER_EXTERNAL_URL', 'https://aibible.onrender.com')

GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '420462376171-neu8kbc7cm1geu2ov70gd10fh9e2210i.apps.googleusercontent.com')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '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')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# Role-based codes
ROLE_CODES = {
    'user': None,  # No code needed
    'host': os.environ.get('HOST_CODE', 'HOST123'),
    'mod': os.environ.get('MOD_CODE', 'MOD456'),
    'co_owner': os.environ.get('CO_OWNER_CODE', 'COOWNER789'),
    'owner': os.environ.get('OWNER_CODE', 'OWNER999')
}

ADMIN_CODE = os.environ.get('ADMIN_CODE', 'God Is All')
MASTER_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'God Is All')

DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///bible_ios.db')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

IS_POSTGRES = DATABASE_URL and ('postgresql' in DATABASE_URL or 'postgres' in DATABASE_URL)
BOOK_TEXT_CACHE = {}
BOOK_META_CACHE = {}

def get_db():
    """Get database connection - PostgreSQL for Render, SQLite for local"""
    if IS_POSTGRES:
        try:
            import psycopg2
            import psycopg2.extras
            conn = psycopg2.connect(DATABASE_URL, sslmode='require')
            return conn, 'postgres'
        except ImportError:
            logger.warning("psycopg2 not installed, falling back to SQLite")
            conn = sqlite3.connect('bible_ios.db', timeout=20)
            conn.row_factory = sqlite3.Row
            return conn, 'sqlite'
        except Exception as e:
            logger.error(f"PostgreSQL connection failed: {e}")
            # Fallback to SQLite if Postgres fails
            conn = sqlite3.connect('bible_ios.db', timeout=20)
            conn.row_factory = sqlite3.Row
            return conn, 'sqlite'
    else:
        conn = sqlite3.connect('bible_ios.db', timeout=20)
        conn.row_factory = sqlite3.Row
        return conn, 'sqlite'

def get_cursor(conn, db_type):
    """Get cursor with dict access"""
    if db_type == 'postgres':
        import psycopg2.extras
        return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        return conn.cursor()

def read_system_setting(key, default=None):
    conn = None
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        c.execute("""
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        if db_type == 'postgres':
            c.execute("SELECT value FROM system_settings WHERE key = %s", (key,))
        else:
            c.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
        row = c.fetchone()
        conn.close()
        if not row:
            return default
        if hasattr(row, 'keys'):
            return row.get('value', default)
        return row[0] if row[0] is not None else default
    except Exception:
        if conn:
            try:
                conn.close()
            except:
                pass
        return default

def init_db():
    """Initialize database tables"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute('''
                CREATE TABLE IF NOT EXISTS verses (
                    id SERIAL PRIMARY KEY, reference TEXT, text TEXT, 
                    translation TEXT, source TEXT, timestamp TEXT, book TEXT
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY, google_id TEXT UNIQUE, email TEXT, 
                    name TEXT, picture TEXT, created_at TEXT, is_admin INTEGER DEFAULT 0,
                    is_banned BOOLEAN DEFAULT FALSE, ban_expires_at TIMESTAMP, ban_reason TEXT, role TEXT DEFAULT 'user'
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS likes (
                    id SERIAL PRIMARY KEY, user_id INTEGER, verse_id INTEGER, 
                    timestamp TEXT, UNIQUE(user_id, verse_id)
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS saves (
                    id SERIAL PRIMARY KEY, user_id INTEGER, verse_id INTEGER, 
                    timestamp TEXT, UNIQUE(user_id, verse_id)
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS comments (
                    id SERIAL PRIMARY KEY, user_id INTEGER, verse_id INTEGER,
                    text TEXT, timestamp TEXT, google_name TEXT, google_picture TEXT,
                    is_deleted INTEGER DEFAULT 0
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS collections (
                    id SERIAL PRIMARY KEY, user_id INTEGER, name TEXT, 
                    color TEXT, created_at TEXT
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS verse_collections (
                    id SERIAL PRIMARY KEY, collection_id INTEGER, verse_id INTEGER,
                    UNIQUE(collection_id, verse_id)
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS community_messages (
                    id SERIAL PRIMARY KEY, user_id INTEGER, text TEXT, 
                    timestamp TEXT, google_name TEXT, google_picture TEXT
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS comment_reactions (
                    id SERIAL PRIMARY KEY,
                    item_type TEXT NOT NULL,
                    item_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    reaction TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(item_type, item_id, user_id, reaction)
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS comment_replies (
                    id SERIAL PRIMARY KEY,
                    parent_type TEXT NOT NULL,
                    parent_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    text TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    google_name TEXT,
                    google_picture TEXT,
                    is_deleted INTEGER DEFAULT 0
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS daily_actions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    verse_id INTEGER,
                    event_date TEXT NOT NULL,
                    timestamp TEXT,
                    UNIQUE(user_id, action, verse_id, event_date)
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY, admin_id TEXT,
                    action TEXT, target_user_id INTEGER, details TEXT,
                    ip_address TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS bans (
                    id SERIAL PRIMARY KEY, user_id INTEGER UNIQUE,
                    reason TEXT, banned_by TEXT, banned_at TIMESTAMP,
                    expires_at TIMESTAMP
                )
            ''')
        else:
            # SQLite tables
            c.execute('''CREATE TABLE IF NOT EXISTS verses 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT, text TEXT, 
                          translation TEXT, source TEXT, timestamp TEXT, book TEXT)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS users 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, google_id TEXT UNIQUE, email TEXT, 
                          name TEXT, picture TEXT, created_at TEXT, is_admin INTEGER DEFAULT 0,
                          is_banned INTEGER DEFAULT 0, ban_expires_at TEXT, ban_reason TEXT, role TEXT DEFAULT 'user')''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS likes 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, verse_id INTEGER, 
                          timestamp TEXT, UNIQUE(user_id, verse_id))''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS saves 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, verse_id INTEGER, 
                          timestamp TEXT, UNIQUE(user_id, verse_id))''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS comments 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, verse_id INTEGER,
                          text TEXT, timestamp TEXT, google_name TEXT, google_picture TEXT,
                          is_deleted INTEGER DEFAULT 0)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS collections 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, 
                          color TEXT, created_at TEXT)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS verse_collections 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, collection_id INTEGER, verse_id INTEGER,
                          UNIQUE(collection_id, verse_id))''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS community_messages 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, text TEXT, 
                          timestamp TEXT, google_name TEXT, google_picture TEXT)''')

            c.execute('''CREATE TABLE IF NOT EXISTS comment_reactions
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, item_type TEXT NOT NULL, item_id INTEGER NOT NULL,
                          user_id INTEGER NOT NULL, reaction TEXT NOT NULL, timestamp TEXT,
                          UNIQUE(item_type, item_id, user_id, reaction))''')

            c.execute('''CREATE TABLE IF NOT EXISTS comment_replies
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, parent_type TEXT NOT NULL, parent_id INTEGER NOT NULL,
                          user_id INTEGER NOT NULL, text TEXT NOT NULL, timestamp TEXT, google_name TEXT,
                          google_picture TEXT, is_deleted INTEGER DEFAULT 0)''')

            c.execute('''CREATE TABLE IF NOT EXISTS daily_actions
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, action TEXT NOT NULL,
                          verse_id INTEGER, event_date TEXT NOT NULL, timestamp TEXT,
                          UNIQUE(user_id, action, verse_id, event_date))''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS audit_logs 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id TEXT,
                          action TEXT, target_user_id INTEGER, details TEXT,
                          ip_address TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS bans 
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE,
                          reason TEXT, banned_by TEXT, banned_at TIMESTAMP,
                          expires_at TIMESTAMP)''')
        
        conn.commit()
        logger.info(f"Database initialized ({db_type})")
    except Exception as e:
        logger.error(f"DB Init Error: {e}")
    finally:
        conn.close()

def migrate_db():
    """Run database migrations to add missing columns"""
    conn, db_type = get_db()
    c = conn.cursor()
    
    try:
        logger.info(f"Running database migrations ({db_type})...")
        
        if db_type == 'postgres':
            # Add is_deleted column to comments table
            try:
                c.execute("ALTER TABLE comments ADD COLUMN IF NOT EXISTS is_deleted INTEGER DEFAULT 0")
                logger.info("Added is_deleted column to comments")
            except Exception as e:
                logger.warning(f"is_deleted column may already exist: {e}")
            
            # Add ip_address column to audit_logs table
            try:
                c.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS ip_address TEXT")
                logger.info("Added ip_address column to audit_logs")
            except Exception as e:
                logger.warning(f"ip_address column may already exist: {e}")
                
            # Add target_user_id column to audit_logs if missing
            try:
                c.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS target_user_id INTEGER")
                logger.info("Added target_user_id column to audit_logs")
            except Exception as e:
                logger.warning(f"target_user_id column may already exist: {e}")
            
            # Create comment_restrictions table if not exists
            try:
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
                logger.info("Created comment_restrictions table")
            except Exception as e:
                logger.warning(f"comment_restrictions table may already exist: {e}")

            try:
                c.execute("""
                    CREATE TABLE IF NOT EXISTS comment_reactions (
                        id SERIAL PRIMARY KEY,
                        item_type TEXT NOT NULL,
                        item_id INTEGER NOT NULL,
                        user_id INTEGER NOT NULL,
                        reaction TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(item_type, item_id, user_id, reaction)
                    )
                """)
                logger.info("Created comment_reactions table")
            except Exception as e:
                logger.warning(f"comment_reactions table may already exist: {e}")

            try:
                c.execute("""
                    CREATE TABLE IF NOT EXISTS comment_replies (
                        id SERIAL PRIMARY KEY,
                        parent_type TEXT NOT NULL,
                        parent_id INTEGER NOT NULL,
                        user_id INTEGER NOT NULL,
                        text TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        google_name TEXT,
                        google_picture TEXT,
                        is_deleted INTEGER DEFAULT 0
                    )
                """)
                logger.info("Created comment_replies table")
            except Exception as e:
                logger.warning(f"comment_replies table may already exist: {e}")

            try:
                c.execute("""
                    CREATE TABLE IF NOT EXISTS daily_actions (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        action TEXT NOT NULL,
                        verse_id INTEGER,
                        event_date TEXT NOT NULL,
                        timestamp TEXT,
                        UNIQUE(user_id, action, verse_id, event_date)
                    )
                """)
                logger.info("Created daily_actions table")
            except Exception as e:
                logger.warning(f"daily_actions table may already exist: {e}")
                
        else:
            # SQLite migrations
            # Check if is_deleted column exists in comments
            try:
                c.execute("SELECT is_deleted FROM comments LIMIT 1")
            except:
                try:
                    c.execute("ALTER TABLE comments ADD COLUMN is_deleted INTEGER DEFAULT 0")
                    logger.info("Added is_deleted column to comments")
                except Exception as e:
                    logger.warning(f"Could not add is_deleted: {e}")
            
            # Check if ip_address column exists in audit_logs
            try:
                c.execute("SELECT ip_address FROM audit_logs LIMIT 1")
            except:
                try:
                    c.execute("ALTER TABLE audit_logs ADD COLUMN ip_address TEXT")
                    logger.info("Added ip_address column to audit_logs")
                except Exception as e:
                    logger.warning(f"Could not add ip_address: {e}")
            
            # Check if target_user_id column exists in audit_logs
            try:
                c.execute("SELECT target_user_id FROM audit_logs LIMIT 1")
            except:
                try:
                    c.execute("ALTER TABLE audit_logs ADD COLUMN target_user_id INTEGER")
                    logger.info("Added target_user_id column to audit_logs")
                except Exception as e:
                    logger.warning(f"Could not add target_user_id: {e}")
            
            # Create comment_restrictions table if not exists
            try:
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
                logger.info("Created comment_restrictions table")
            except Exception as e:
                logger.warning(f"comment_restrictions table may already exist: {e}")

            try:
                c.execute("""
                    CREATE TABLE IF NOT EXISTS comment_reactions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        item_type TEXT NOT NULL,
                        item_id INTEGER NOT NULL,
                        user_id INTEGER NOT NULL,
                        reaction TEXT NOT NULL,
                        timestamp TEXT,
                        UNIQUE(item_type, item_id, user_id, reaction)
                    )
                """)
                logger.info("Created comment_reactions table")
            except Exception as e:
                logger.warning(f"comment_reactions table may already exist: {e}")

            try:
                c.execute("""
                    CREATE TABLE IF NOT EXISTS comment_replies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        parent_type TEXT NOT NULL,
                        parent_id INTEGER NOT NULL,
                        user_id INTEGER NOT NULL,
                        text TEXT NOT NULL,
                        timestamp TEXT,
                        google_name TEXT,
                        google_picture TEXT,
                        is_deleted INTEGER DEFAULT 0
                    )
                """)
                logger.info("Created comment_replies table")
            except Exception as e:
                logger.warning(f"comment_replies table may already exist: {e}")

            try:
                c.execute("""
                    CREATE TABLE IF NOT EXISTS daily_actions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        action TEXT NOT NULL,
                        verse_id INTEGER,
                        event_date TEXT NOT NULL,
                        timestamp TEXT,
                        UNIQUE(user_id, action, verse_id, event_date)
                    )
                """)
                logger.info("Created daily_actions table")
            except Exception as e:
                logger.warning(f"daily_actions table may already exist: {e}")
        
        conn.commit()
        logger.info("Database migrations completed")
    except Exception as e:
        logger.error(f"Migration error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

init_db()
migrate_db()

def record_daily_action(user_id, action, verse_id=None):
    """Persist unique per-day user actions used by Daily Challenge."""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    today = datetime.now().date().isoformat()
    now = datetime.now().isoformat()

    try:
        if db_type == 'postgres':
            c.execute("""
                INSERT INTO daily_actions (user_id, action, verse_id, event_date, timestamp)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (user_id, action, verse_id, event_date) DO NOTHING
            """, (user_id, action, verse_id, today, now))
        else:
            c.execute("""
                INSERT OR IGNORE INTO daily_actions (user_id, action, verse_id, event_date, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, action, verse_id, today, now))
        conn.commit()
    except Exception as e:
        logger.warning(f"Daily action record failed: {e}")
    finally:
        conn.close()

def log_action(admin_id, action, target_user_id=None, details=None):
    """Log admin actions for audit trail"""
    try:
        from flask import request
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        try:
            ip = request.remote_addr
        except:
            ip = 'system'
        
        if db_type == 'postgres':
            c.execute("INSERT INTO audit_logs (admin_id, action, target_user_id, details, ip_address) VALUES (%s, %s, %s, %s, %s)",
                      (admin_id, action, target_user_id, json.dumps(details) if details else None, ip))
        else:
            c.execute("INSERT INTO audit_logs (admin_id, action, target_user_id, details, ip_address) VALUES (?, ?, ?, ?, ?)",
                      (admin_id, action, target_user_id, json.dumps(details) if details else None, ip))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Log error: {e}")

def ensure_comment_social_tables(c, db_type):
    """Ensure reactions/replies tables exist before use."""
    if db_type == 'postgres':
        c.execute("""
            CREATE TABLE IF NOT EXISTS comment_reactions (
                id SERIAL PRIMARY KEY,
                item_type TEXT NOT NULL,
                item_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                reaction TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(item_type, item_id, user_id, reaction)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS comment_replies (
                id SERIAL PRIMARY KEY,
                parent_type TEXT NOT NULL,
                parent_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                text TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                google_name TEXT,
                google_picture TEXT,
                is_deleted INTEGER DEFAULT 0
            )
        """)
    else:
        c.execute("""
            CREATE TABLE IF NOT EXISTS comment_reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_type TEXT NOT NULL,
                item_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                reaction TEXT NOT NULL,
                timestamp TEXT,
                UNIQUE(item_type, item_id, user_id, reaction)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS comment_replies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                parent_type TEXT NOT NULL,
                parent_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                text TEXT NOT NULL,
                timestamp TEXT,
                google_name TEXT,
                google_picture TEXT,
                is_deleted INTEGER DEFAULT 0
            )
        """)

def get_reaction_counts(c, db_type, item_type, item_id):
    reactions = {"heart": 0, "pray": 0, "cross": 0}
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
    for row in c.fetchall():
        try:
            key = str(row['reaction']).lower()
            cnt = int(row['cnt'])
        except Exception:
            key = str(row[0]).lower()
            cnt = int(row[1])
        if key in reactions:
            reactions[key] = cnt
    return reactions

def get_replies_for_parent(c, db_type, parent_type, parent_id):
    if db_type == 'postgres':
        c.execute("""
            SELECT
                r.id, r.user_id, r.text, r.timestamp, r.google_name, r.google_picture,
                u.name AS db_name, u.picture AS db_picture, u.role AS db_role
            FROM comment_replies r
            LEFT JOIN users u ON r.user_id = u.id
            WHERE r.parent_type = %s AND r.parent_id = %s AND COALESCE(r.is_deleted, 0) = 0
            ORDER BY r.timestamp ASC
        """, (parent_type, parent_id))
    else:
        c.execute("""
            SELECT
                r.id, r.user_id, r.text, r.timestamp, r.google_name, r.google_picture,
                u.name AS db_name, u.picture AS db_picture, u.role AS db_role
            FROM comment_replies r
            LEFT JOIN users u ON r.user_id = u.id
            WHERE r.parent_type = ? AND r.parent_id = ? AND COALESCE(r.is_deleted, 0) = 0
            ORDER BY r.timestamp ASC
        """, (parent_type, parent_id))
    rows = c.fetchall()
    replies = []
    for row in rows:
        try:
            reply_id = row['id']
            user_id = row['user_id']
            text = row['text']
            timestamp = row['timestamp']
            google_name = row['google_name']
            google_picture = row['google_picture']
            db_name = row.get('db_name')
            db_picture = row.get('db_picture')
            db_role = row.get('db_role')
        except Exception:
            reply_id = row[0]
            user_id = row[1]
            text = row[2]
            timestamp = row[3]
            google_name = row[4]
            google_picture = row[5]
            db_name = row[6] if len(row) > 6 else None
            db_picture = row[7] if len(row) > 7 else None
            db_role = row[8] if len(row) > 8 else None
        replies.append({
            "id": reply_id,
            "user_id": user_id,
            "text": text or "",
            "timestamp": timestamp,
            "user_name": db_name or google_name or "Anonymous",
            "user_picture": db_picture or google_picture or "",
            "user_role": db_role or "user"
        })
    return replies

def check_ban_status(user_id):
    """Check if user is currently banned. Returns (is_banned, reason, expires_at)"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("SELECT is_banned, ban_expires_at, ban_reason FROM users WHERE id = %s", (user_id,))
        else:
            c.execute("SELECT is_banned, ban_expires_at, ban_reason FROM users WHERE id = ?", (user_id,))
        
        row = c.fetchone()
        conn.close()
        
        if not row:
            return (False, None, None)
        
        try:
            is_banned = bool(row['is_banned'])
            expires_at = row['ban_expires_at']
            reason = row['ban_reason']
        except (TypeError, KeyError):
            is_banned = bool(row[0])
            expires_at = row[1]
            reason = row[2]
        
        # Check if temporary ban expired
        if is_banned and expires_at:
            try:
                expire_dt = datetime.fromisoformat(str(expires_at))
                if datetime.now() > expire_dt:
                    # Auto-unban
                    conn, db_type = get_db()
                    c = get_cursor(conn, db_type)
                    if db_type == 'postgres':
                        c.execute("UPDATE users SET is_banned = FALSE, ban_expires_at = NULL, ban_reason = NULL WHERE id = %s", (user_id,))
                    else:
                        c.execute("UPDATE users SET is_banned = 0, ban_expires_at = NULL, ban_reason = NULL WHERE id = ?", (user_id,))
                    conn.commit()
                    conn.close()
                    return (False, None, None)
            except:
                pass
        
        return (is_banned, reason, expires_at)
    except Exception as e:
        logger.error(f"Ban check error: {e}")
        conn.close()
        return (False, None, None)

# Register admin blueprint
from admin import admin_bp
app.register_blueprint(admin_bp)

class BibleGenerator:
    def __init__(self):
        self.running = True
        self.interval = self._load_interval_from_db()
        self.time_left = self.interval
        self.current_verse = None
        self.total_verses = 0
        self.session_id = secrets.token_hex(8)
        self.thread = None
        self.lock = threading.Lock()
        
        # Fallback verses in case API fails
        self.fallback_verses = [
            {"id": 1, "ref": "John 3:16", "text": "For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life.", "trans": "KJV", "source": "Fallback", "book": "John"},
            {"id": 2, "ref": "Philippians 4:13", "text": "I can do all things through Christ which strengtheneth me.", "trans": "KJV", "source": "Fallback", "book": "Philippians"},
            {"id": 3, "ref": "Psalm 23:1", "text": "The LORD is my shepherd; I shall not want.", "trans": "KJV", "source": "Fallback", "book": "Psalm"},
            {"id": 4, "ref": "Romans 8:28", "text": "And we know that all things work together for good to them that love God, to them who are the called according to his purpose.", "trans": "KJV", "source": "Fallback", "book": "Romans"},
            {"id": 5, "ref": "Jeremiah 29:11", "text": "For I know the thoughts that I think toward you, saith the LORD, thoughts of peace, and not of evil, to give you an expected end.", "trans": "KJV", "source": "Fallback", "book": "Jeremiah"}
        ]
        
        # Try to load most recent verse from database first
        try:
            conn, db_type = get_db()
            c = get_cursor(conn, db_type)
            c.execute("SELECT id, reference, text, translation, source, book FROM verses ORDER BY timestamp DESC LIMIT 1")
            row = c.fetchone()
            conn.close()
            
            if row:
                # Use most recent verse from database
                try:
                    verse_id = row['id'] if hasattr(row, 'keys') else row[0]
                    ref = row['reference'] if hasattr(row, 'keys') else row[1]
                    text = row['text'] if hasattr(row, 'keys') else row[2]
                    trans = row['translation'] if hasattr(row, 'keys') else row[3]
                    source = row['source'] if hasattr(row, 'keys') else row[4]
                    book = row['book'] if hasattr(row, 'keys') else row[5]
                except:
                    verse_id, ref, text, trans, source, book = row
                
                self.current_verse = {
                    "id": verse_id,
                    "ref": ref,
                    "text": text,
                    "trans": trans,
                    "source": source,
                    "book": book,
                    "is_new": False,
                    "session_id": self.session_id
                }
                logger.info(f"Loaded verse from database: {ref}")
            else:
                # No verses in database, use fallback
                self.current_verse = random.choice(self.fallback_verses)
                self.current_verse['session_id'] = self.session_id
        except Exception as e:
            logger.error(f"Failed to load verse from DB: {e}")
            # Start with fallback verse
            self.current_verse = random.choice(self.fallback_verses)
            self.current_verse['session_id'] = self.session_id
        
        self.networks = [
            {"name": "Bible-API.com", "url": "https://bible-api.com/?random=verse"},
            {"name": "labs.bible.org", "url": "https://labs.bible.org/api/?passage=random&type=json"},
            {"name": "KJV Random", "url": "https://bible-api.com/?random=verse&translation=kjv"}
        ]
        self.network_idx = 0
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        
        # Start thread
        self.start_thread()
    
    def _load_interval_from_db(self):
        """Load verse interval from database, default to 60 seconds"""
        try:
            conn, db_type = get_db()
            c = conn.cursor()
            
            # Ensure table exists
            c.execute("""
                CREATE TABLE IF NOT EXISTS system_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            
            # Get verse_interval setting
            c.execute("SELECT value FROM system_settings WHERE key = 'verse_interval'")
            row = c.fetchone()
            conn.close()
            
            if row:
                interval = int(row[0])
                logger.info(f"Loaded verse interval from database: {interval} seconds")
                return interval
        except Exception as e:
            logger.error(f"Failed to load interval from DB: {e}")
        
        return 60  # Default to 60 seconds
    
    def start_thread(self):
        """Start or restart the generator thread"""
        if self.thread is None or not self.thread.is_alive():
            self.thread = threading.Thread(target=self.loop)
            self.thread.daemon = True
            self.thread.start()
            logger.info("BibleGenerator thread started")
    
    def set_interval(self, seconds):
        with self.lock:
            self.interval = max(10, min(3600, int(seconds)))
            self.time_left = min(self.time_left, self.interval)
    
    def extract_book(self, ref):
        match = re.match(r'^([0-9]?\s?[A-Za-z]+)', ref)
        return match.group(1) if match else "Unknown"
    
    def fetch_verse(self):
        """Fetch a new verse from API or use fallback"""
        network = self.networks[self.network_idx]
        verse_data = None
        
        try:
            r = self.session.get(network["url"], timeout=10)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    data = data[0]
                    ref = f"{data['bookname']} {data['chapter']}:{data['verse']}"
                    text = data['text']
                    trans = "WEB"
                else:
                    ref = data.get('reference', 'Unknown')
                    text = data.get('text', '').strip()
                    trans = data.get('translation_name', 'KJV')
                
                if text and ref:
                    book = self.extract_book(ref)
                    verse_data = {
                        "ref": ref,
                        "text": text,
                        "trans": trans,
                        "source": network["name"],
                        "book": book
                    }
        except Exception as e:
            logger.error(f"Fetch error from {network['name']}: {e}")
        
        # Rotate network for next time
        self.network_idx = (self.network_idx + 1) % len(self.networks)
        
        # If API failed, use fallback
        if not verse_data:
            logger.warning("Using fallback verse")
            fallback = random.choice(self.fallback_verses)
            verse_data = {
                "ref": fallback['ref'],
                "text": fallback['text'],
                "trans": fallback['trans'],
                "source": "Fallback",
                "book": fallback['book']
            }
        
        # Store in database
        try:
            conn, db_type = get_db()
            c = get_cursor(conn, db_type)
            
            if db_type == 'postgres':
                c.execute("""
                    INSERT INTO verses (reference, text, translation, source, timestamp, book) 
                    VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING
                """, (verse_data['ref'], verse_data['text'], verse_data['trans'], 
                      verse_data['source'], datetime.now().isoformat(), verse_data['book']))
            else:
                c.execute("INSERT OR IGNORE INTO verses (reference, text, translation, source, timestamp, book) VALUES (?, ?, ?, ?, ?, ?)",
                          (verse_data['ref'], verse_data['text'], verse_data['trans'], 
                           verse_data['source'], datetime.now().isoformat(), verse_data['book']))
            
            conn.commit()
            
            # Get the ID
            if db_type == 'postgres':
                c.execute("SELECT id FROM verses WHERE reference = %s AND text = %s", 
                         (verse_data['ref'], verse_data['text']))
            else:
                c.execute("SELECT id FROM verses WHERE reference = ? AND text = ?", 
                         (verse_data['ref'], verse_data['text']))
            
            result = c.fetchone()
            try:
                verse_id = result['id'] if result else random.randint(1000, 9999)
            except (TypeError, KeyError):
                verse_id = result[0] if result else random.randint(1000, 9999)
            
            # Update session
            self.session_id = secrets.token_hex(8)
            
            conn.close()
            
            with self.lock:
                self.current_verse = {
                    "id": verse_id,
                    "ref": verse_data['ref'],
                    "text": verse_data['text'],
                    "trans": verse_data['trans'],
                    "source": verse_data['source'],
                    "book": verse_data['book'],
                    "is_new": True,
                    "session_id": self.session_id
                }
                self.total_verses += 1
                
            logger.info(f"New verse fetched: {verse_data['ref']}")
            return True
            
        except Exception as e:
            logger.error(f"Database error in fetch_verse: {e}")
            # Still update current_verse even if DB fails
            with self.lock:
                self.current_verse = {
                    "id": random.randint(1000, 9999),
                    "ref": verse_data['ref'],
                    "text": verse_data['text'],
                    "trans": verse_data['trans'],
                    "source": verse_data['source'],
                    "book": verse_data['book'],
                    "is_new": True,
                    "session_id": secrets.token_hex(8)
                }
            return True
    
    def get_current_verse(self):
        """Thread-safe get current verse"""
        with self.lock:
            return self.current_verse.copy() if self.current_verse else None
    
    def get_time_left(self):
        """Thread-safe get time left"""
        with self.lock:
            return self.time_left
    
    def reset_timer(self):
        """Reset the timer after fetching"""
        with self.lock:
            self.time_left = self.interval
    
    def decrement_timer(self):
        """Decrement timer by 1 second"""
        with self.lock:
            self.time_left -= 1
            return self.time_left
    
    def loop(self):
        """Main loop - runs forever"""
        while self.running:
            try:
                current = self.get_time_left()
                if current <= 0:
                    self.fetch_verse()
                    self.reset_timer()
                else:
                    self.decrement_timer()
            except Exception as e:
                logger.error(f"Critical error in generator loop: {e}")
                time.sleep(5)  # Wait before retrying
                continue
            time.sleep(1)

# Global generator instance
generator = BibleGenerator()
CURRENT_API_CACHE_TTL = max(0.5, float(os.environ.get('API_CURRENT_CACHE_TTL', '2.0')))
_current_api_cache = {}
_current_api_cache_lock = threading.Lock()

# Bind the method to the class
def generate_smart_recommendation(self, user_id):
    """Generate recommendation based on user likes"""
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("""
                SELECT DISTINCT v.book FROM verses v 
                JOIN likes l ON v.id = l.verse_id 
                WHERE l.user_id = %s
                UNION
                SELECT DISTINCT v.book FROM verses v 
                JOIN saves s ON v.id = s.verse_id 
                WHERE s.user_id = %s
            """, (user_id, user_id))
        else:
            c.execute("""
                SELECT DISTINCT v.book FROM verses v 
                JOIN likes l ON v.id = l.verse_id 
                WHERE l.user_id = ?
                UNION
                SELECT DISTINCT v.book FROM verses v 
                JOIN saves s ON v.id = s.verse_id 
                WHERE s.user_id = ?
            """, (user_id, user_id))
        
        preferred_books = []
        for row in c.fetchall():
            try:
                preferred_books.append(row['book'])
            except (TypeError, KeyError):
                preferred_books.append(row[0])
        
        if preferred_books:
            if db_type == 'postgres':
                placeholders = ','.join(['%s'] * len(preferred_books))
                c.execute(f"""
                    SELECT v.* FROM verses v
                    WHERE v.book IN ({placeholders})
                    AND v.id NOT IN (SELECT verse_id FROM likes WHERE user_id = %s)
                    AND v.id NOT IN (SELECT verse_id FROM saves WHERE user_id = %s)
                    ORDER BY RANDOM()
                    LIMIT 1
                """, (*preferred_books, user_id, user_id))
            else:
                placeholders = ','.join('?' for _ in preferred_books)
                c.execute(f"""
                    SELECT v.* FROM verses v
                    WHERE v.book IN ({placeholders})
                    AND v.id NOT IN (SELECT verse_id FROM likes WHERE user_id = ?)
                    AND v.id NOT IN (SELECT verse_id FROM saves WHERE user_id = ?)
                    ORDER BY RANDOM()
                    LIMIT 1
                """, (*preferred_books, user_id, user_id))
        else:
            if db_type == 'postgres':
                c.execute("""
                    SELECT * FROM verses 
                    WHERE id NOT IN (SELECT verse_id FROM likes WHERE user_id = %s)
                    ORDER BY RANDOM() LIMIT 1
                """, (user_id,))
            else:
                c.execute("""
                    SELECT * FROM verses 
                    WHERE id NOT IN (SELECT verse_id FROM likes WHERE user_id = ?)
                    ORDER BY RANDOM() LIMIT 1
                """, (user_id,))
        
        row = c.fetchone()
        
        if row:
            try:
                return {
                    "id": row['id'], 
                    "ref": row['reference'], 
                    "text": row['text'],
                    "trans": row['translation'], 
                    "book": row['book'],
                    "reason": f"Because you like {row['book']}" if preferred_books else "Recommended for you"
                }
            except (TypeError, KeyError):
                return {
                    "id": row[0], 
                    "ref": row[1], 
                    "text": row[2],
                    "trans": row[3], 
                    "book": row[6],
                    "reason": f"Because you like {row[6]}" if preferred_books else "Recommended for you"
                }
        return None
    except Exception as e:
        logger.error(f"Recommendation error: {e}")
        return None
    finally:
        conn.close()

BibleGenerator.generate_smart_recommendation = generate_smart_recommendation

@app.before_request
def check_user_banned():
    """Check if current user is banned before processing request"""
    endpoint = request.endpoint or ''
    path = request.path or ''
    public_allow = {'logout', 'check_ban', 'static', 'login', 'google_login', 'callback', 'health', 'manifest', 'serve_audio', 'serve_video'}

    if not path.startswith('/admin') and endpoint not in public_allow:
        maintenance_raw = read_system_setting('maintenance_mode', '0')
        maintenance_enabled = str(maintenance_raw).strip().lower() in ('1', 'true', 'yes', 'on')
        if maintenance_enabled and not session.get('admin_role'):
            if request.is_json or path.startswith('/api/'):
                return jsonify({"error": "maintenance", "message": "Site is under maintenance"}), 503
            return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head><title>Maintenance</title>
            <style>
                body { background: #0a0a0f; color: white; font-family: system-ui; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
                .box { text-align: center; padding: 40px; background: rgba(10,132,255,0.12); border: 1px solid rgba(10,132,255,0.45); border-radius: 20px; max-width: 520px; }
                h1 { color: #6fa7ff; margin-bottom: 14px; }
            </style></head>
            <body>
                <div class="box">
                    <h1>Maintenance Mode</h1>
                    <p>We are upgrading the experience right now. Please check back shortly.</p>
                </div>
            </body>
            </html>
            """), 503

    if 'user_id' in session:
        # Track user presence for admin analytics.
        try:
            conn, db_type = get_db()
            c = get_cursor(conn, db_type)
            c.execute("""
                CREATE TABLE IF NOT EXISTS user_presence (
                    user_id INTEGER PRIMARY KEY,
                    last_seen TEXT,
                    last_path TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            now_iso = datetime.now().isoformat()
            if db_type == 'postgres':
                c.execute("""
                    INSERT INTO user_presence (user_id, last_seen, last_path, updated_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (user_id) DO UPDATE SET
                        last_seen = EXCLUDED.last_seen,
                        last_path = EXCLUDED.last_path,
                        updated_at = EXCLUDED.updated_at
                """, (session['user_id'], now_iso, path, now_iso))
            else:
                c.execute("""
                    INSERT INTO user_presence (user_id, last_seen, last_path, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        last_path = excluded.last_path,
                        updated_at = excluded.updated_at
                """, (session['user_id'], now_iso, path, now_iso))
            conn.commit()
            conn.close()
        except Exception:
            pass

        if endpoint in public_allow:
            return None

        if request.endpoint in ['logout', 'check_ban', 'static', 'login', 'google_login', 'callback', 'health']:
            return None
        
        is_banned, reason, _ = check_ban_status(session['user_id'])
        if is_banned:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({"error": "banned", "reason": reason, "message": "Your account has been banned"}), 403
            else:
                return render_template_string("""
                <!DOCTYPE html>
                <html>
                <head><title>Account Banned</title>
                <style>
                    body { background: #0a0a0f; color: white; font-family: system-ui; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
                    .ban-container { text-align: center; padding: 40px; background: rgba(255,55,95,0.1); border: 1px solid #ff375f; border-radius: 20px; max-width: 400px; }
                    h1 { color: #ff375f; margin-bottom: 20px; }
                    .reason { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 10px; margin: 20px 0; font-style: italic; }
                    a { color: #0A84FF; text-decoration: none; }
                </style></head>
                <body>
                    <div class="ban-container">
                        <h1>⛔ Account Banned</h1>
                        <p>Your account has been suspended.</p>
                        {% if reason %}
                        <div class="reason">Reason: {{ reason }}</div>
                        {% endif %}
                        <p><a href="/logout">Logout</a></p>
                    </div>
                </body>
                </html>
                """, reason=reason), 403

@app.route('/health')
def health_check():
    """Health check endpoint to verify generator is running"""
    try:
        status = {
            "status": "healthy",
            "generator_running": generator.thread.is_alive() if generator.thread else False,
            "current_verse": generator.get_current_verse()['ref'] if generator.get_current_verse() else None,
            "time_left": generator.get_time_left(),
            "interval": generator.interval
        }
        return jsonify(status)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route('/static/audio/<path:filename>')
def serve_audio(filename):
    return send_from_directory(os.path.join(app.root_path, 'static', 'audio'), filename)

@app.route('/media/videos/<path:filename>')
def serve_video(filename):
    """Serve About videos from multiple safe locations for production compatibility."""
    allowed = {'1.mp4', '2.mp4'}
    if filename not in allowed:
        return jsonify({"error": "not_found"}), 404

    search_dirs = [
        os.path.join(app.root_path, 'static', 'videos'),
        os.path.join(app.root_path, 'static', 'audio'),
        app.root_path,
        os.getcwd()
    ]

    # Fast direct checks first.
    for directory in search_dirs:
        full_path = os.path.join(directory, filename)
        if os.path.isfile(full_path):
            return send_from_directory(directory, filename)

    # Fallback: recursive search under app roots in case Render root differs.
    seen = set()
    for base in [app.root_path, os.getcwd()]:
        if not os.path.isdir(base):
            continue
        for root, _, files in os.walk(base):
            if filename in files:
                abs_path = os.path.join(root, filename)
                if abs_path in seen:
                    continue
                seen.add(abs_path)
                return send_from_directory(root, filename)

    return jsonify({
        "error": "not_found",
        "message": "Video file missing on server",
        "root_path": app.root_path,
        "cwd": os.getcwd()
    }), 404

@app.route('/manifest.json')
def manifest():
    return jsonify({
        "name": "Bible AI",
        "short_name": "BibleAI",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#000000",
        "theme_color": "#0A84FF",
        "icons": [{"src": "/static/icon.png", "sizes": "192x192"}]
    })

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    is_banned, reason, _ = check_ban_status(session['user_id'])
    if is_banned:
        return redirect(url_for('logout'))
    
    # Ensure generator thread is running
    generator.start_thread()
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
        else:
            c.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        
        user = c.fetchone()
        
        if db_type == 'postgres':
            c.execute("SELECT COUNT(*) as count FROM verses")
            total_verses = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM likes WHERE user_id = %s", (session['user_id'],))
            liked_count = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM saves WHERE user_id = %s", (session['user_id'],))
            saved_count = c.fetchone()['count']
        else:
            c.execute("SELECT COUNT(*) as count FROM verses")
            try:
                total_verses = c.fetchone()[0]
            except:
                total_verses = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM likes WHERE user_id = ?", (session['user_id'],))
            try:
                liked_count = c.fetchone()[0]
            except:
                liked_count = c.fetchone()['count']
            c.execute("SELECT COUNT(*) as count FROM saves WHERE user_id = ?", (session['user_id'],))
            try:
                saved_count = c.fetchone()[0]
            except:
                saved_count = c.fetchone()['count']
        
        if not user:
            session.clear()
            return redirect(url_for('login'))
        
        try:
            user_dict = {
                "id": user['id'],
                "name": user['name'],
                "email": user['email'],
                "picture": user['picture'],
                "role": user.get('role', 'user') if isinstance(user, dict) else (user[10] if len(user) > 10 else 'user')
            }
        except (TypeError, KeyError):
            user_dict = {
                "id": user[0],
                "name": user[3],
                "email": user[2],
                "picture": user[4],
                "role": user[10] if len(user) > 10 else 'user'
            }
        
        return render_template('web.html', 
                             user=user_dict,
                             stats={"total_verses": total_verses, "liked": liked_count, "saved": saved_count})
    except Exception as e:
        logger.error(f"Index error: {e}")
        return f"Error loading page: {e}", 500
    finally:
        conn.close()

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/google-login')
def google_login():
    try:
        google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
        authorization_endpoint = google_provider_cfg["authorization_endpoint"]
        callback_url = PUBLIC_URL + "/callback"
        state = secrets.token_urlsafe(16)
        session['oauth_state'] = state
        
        auth_url = (
            f"{authorization_endpoint}"
            f"?client_id={GOOGLE_CLIENT_ID}"
            f"&redirect_uri={callback_url}"
            f"&response_type=code"
            f"&scope=openid%20email%20profile"
            f"&state={state}"
        )
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"Google login error: {e}")
        return f"Error initiating Google login: {str(e)}", 500

@app.route('/callback')
def callback():
    code = request.args.get("code")
    error = request.args.get("error")
    state = request.args.get("state")
    
    if error:
        return f"OAuth Error: {error}. Please check that this URL ({PUBLIC_URL}) is authorized in Google Cloud Console.", 400
    if not code:
        return "No authorization code received", 400
    if state != session.get('oauth_state'):
        return "Invalid state parameter (CSRF protection)", 400
    
    try:
        google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
        token_endpoint = google_provider_cfg["token_endpoint"]
        callback_url = PUBLIC_URL + "/callback"
        
        token_response = requests.post(
            token_endpoint,
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
            },
        )
        
        if not token_response.ok:
            error_data = token_response.json()
            error_desc = error_data.get('error_description', 'Unknown error')
            return f"Token exchange failed: {error_desc}. Make sure {callback_url} is in your Google Cloud Console authorized redirect URIs.", 400
        
        tokens = token_response.json()
        access_token = tokens.get("access_token")
        
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        userinfo_response = requests.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if not userinfo_response.ok:
            return "Failed to get user info from Google", 400
        
        userinfo = userinfo_response.json()
        google_id = userinfo['sub']
        email = userinfo['email']
        name = userinfo.get('name', email.split('@')[0])
        picture = userinfo.get('picture', '')
        
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        if db_type == 'postgres':
            c.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
        else:
            c.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
        
        user = c.fetchone()
        
        if not user:
            if db_type == 'postgres':
                c.execute("INSERT INTO users (google_id, email, name, picture, created_at, is_admin, is_banned, role) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                          (google_id, email, name, picture, datetime.now().isoformat(), 0, False, 'user'))
            else:
                c.execute("INSERT INTO users (google_id, email, name, picture, created_at, is_admin, is_banned, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                          (google_id, email, name, picture, datetime.now().isoformat(), 0, 0, 'user'))
            conn.commit()
            
            if db_type == 'postgres':
                c.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
            else:
                c.execute("SELECT * FROM users WHERE google_id = ?", (google_id,))
            user = c.fetchone()
        
        conn.close()
        
        # Check if banned
        try:
            user_id = user['id'] if isinstance(user, dict) else user[0]
        except (TypeError, KeyError):
            user_id = user[0]
        
        is_banned, reason, _ = check_ban_status(user_id)
        if is_banned:
            return render_template_string("""
            <h1>Account Banned</h1>
            <p>Your account has been banned.</p>
            <p>Reason: {{ reason }}</p>
            <a href="/logout">Logout</a>
            """, reason=reason), 403
        
        session['user_id'] = user_id
        session['user_name'] = user['name'] if isinstance(user, dict) else user[3]
        session['user_picture'] = user['picture'] if isinstance(user, dict) else user[4]
        session['is_admin'] = bool(user['is_admin']) if isinstance(user, dict) else bool(user[6])
        
        try:
            session['role'] = user['role'] if isinstance(user, dict) else (user[10] if len(user) > 10 else 'user')
        except (TypeError, KeyError):
            session['role'] = user[10] if len(user) > 10 else 'user'
        
        return redirect(url_for('index'))
        
    except Exception as e:
        logger.error(f"Callback error: {e}")
        import traceback
        traceback.print_exc()
        return f"Authentication error: {str(e)}. Please contact support.", 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/check_ban')
def check_ban():
    if 'user_id' not in session:
        return jsonify({"banned": False})
    
    is_banned, reason, expires_at = check_ban_status(session['user_id'])
    return jsonify({
        "banned": is_banned,
        "reason": reason,
        "expires_at": expires_at
    })

@app.route('/api/current')
def get_current():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401

    user_id = session['user_id']
    now = time.time()
    with _current_api_cache_lock:
        cached = _current_api_cache.get(user_id)
        if cached and (now - cached['timestamp']) < CURRENT_API_CACHE_TTL:
            return jsonify(cached['payload'])

    is_banned, _, _ = check_ban_status(user_id)
    if is_banned:
        return jsonify({"error": "banned", "message": "Account banned"}), 403

    # Ensure thread is running
    generator.start_thread()

    payload = {
        "verse": generator.get_current_verse(),
        "countdown": generator.get_time_left(),
        "total_verses": generator.total_verses,
        "session_id": generator.session_id,
        "interval": generator.interval
    }
    with _current_api_cache_lock:
        _current_api_cache[user_id] = {
            "timestamp": now,
            "payload": payload
        }
    return jsonify(payload)

def _pick_book_text_url(formats):
    if not isinstance(formats, dict):
        return None
    preferred = [
        'text/plain; charset=utf-8',
        'text/plain; charset=us-ascii',
        'text/plain'
    ]
    for key in preferred:
        val = formats.get(key)
        if isinstance(val, str) and val.startswith('http'):
            return val
    for key, val in formats.items():
        if isinstance(key, str) and key.startswith('text/plain') and isinstance(val, str) and val.startswith('http'):
            return val
    return None

def _strip_gutenberg_boilerplate(text):
    if not text:
        return ''
    cleaned = text
    start_markers = [
        '*** START OF THE PROJECT GUTENBERG EBOOK',
        '*** START OF THIS PROJECT GUTENBERG EBOOK'
    ]
    end_markers = [
        '*** END OF THE PROJECT GUTENBERG EBOOK',
        '*** END OF THIS PROJECT GUTENBERG EBOOK'
    ]
    for marker in start_markers:
        idx = cleaned.find(marker)
        if idx != -1:
            nl = cleaned.find('\n', idx)
            if nl != -1:
                cleaned = cleaned[nl + 1:]
            break
    for marker in end_markers:
        idx = cleaned.find(marker)
        if idx != -1:
            cleaned = cleaned[:idx]
            break
    cleaned = re.sub(r'\r\n?', '\n', cleaned)
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned).strip()
    return cleaned

@app.route('/api/books/search')
def books_search():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401

    q = (request.args.get('q') or 'faith').strip()
    if len(q) < 2:
        q = 'faith'

    try:
        resp = requests.get('https://gutendex.com/books', params={'search': q}, timeout=15)
        if not resp.ok:
            return jsonify({"error": "book_search_failed"}), 502
        payload = resp.json() or {}
        results = payload.get('results') or []

        q_terms = [t for t in re.split(r'\W+', q.lower()) if t]
        books = []
        for b in results[:20]:
            title = (b.get('title') or '').strip()
            authors = b.get('authors') or []
            author_name = ', '.join([(a.get('name') or '').strip() for a in authors if a.get('name')]) or 'Unknown'
            subjects = b.get('subjects') or []
            formats = b.get('formats') or {}
            text_url = _pick_book_text_url(formats)
            if not text_url:
                continue

            haystack = f"{title} {' '.join(subjects)} {author_name}".lower()
            score = 0
            for term in q_terms:
                if term and term in haystack:
                    score += 2
            score += int((b.get('download_count') or 0) / 1000)

            entry = {
                "id": b.get('id'),
                "title": title,
                "author": author_name,
                "downloads": b.get('download_count') or 0,
                "cover": (formats.get('image/jpeg') or formats.get('image/png') or ''),
                "text_url": text_url,
                "ai_score": score
            }
            BOOK_META_CACHE[str(entry["id"])] = entry
            books.append(entry)

        books.sort(key=lambda x: (x["ai_score"], x["downloads"]), reverse=True)
        return jsonify({"query": q, "books": books[:12]})
    except Exception as e:
        logger.error(f"Book search error: {e}")
        return jsonify({"error": "book_search_error"}), 500

@app.route('/api/books/content/<int:book_id>')
def books_content(book_id):
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401

    key = str(book_id)
    cached = BOOK_TEXT_CACHE.get(key)
    if cached:
        return jsonify(cached)

    try:
        meta = BOOK_META_CACHE.get(key)
        if not meta:
            meta_resp = requests.get(f'https://gutendex.com/books/{book_id}', timeout=15)
            if not meta_resp.ok:
                return jsonify({"error": "book_not_found"}), 404
            b = meta_resp.json() or {}
            formats = b.get('formats') or {}
            meta = {
                "id": book_id,
                "title": (b.get('title') or '').strip() or f'Book {book_id}',
                "author": ', '.join([(a.get('name') or '').strip() for a in (b.get('authors') or []) if a.get('name')]) or 'Unknown',
                "cover": (formats.get('image/jpeg') or formats.get('image/png') or ''),
                "text_url": _pick_book_text_url(formats)
            }
            BOOK_META_CACHE[key] = meta

        text_url = meta.get('text_url')
        if not text_url:
            return jsonify({"error": "book_text_unavailable"}), 404

        text_resp = requests.get(text_url, timeout=20)
        if not text_resp.ok:
            return jsonify({"error": "book_text_fetch_failed"}), 502

        raw = text_resp.text or ''
        cleaned = _strip_gutenberg_boilerplate(raw)
        if len(cleaned) < 200:
            return jsonify({"error": "book_text_too_short"}), 422

        # Keep payload reasonable for client rendering.
        cleaned = cleaned[:800000]

        payload = {
            "id": book_id,
            "title": meta.get('title') or f'Book {book_id}',
            "author": meta.get('author') or 'Unknown',
            "cover": meta.get('cover') or '',
            "text": cleaned
        }
        BOOK_TEXT_CACHE[key] = payload
        return jsonify(payload)
    except Exception as e:
        logger.error(f"Book content error: {e}")
        return jsonify({"error": "book_content_error"}), 500

@app.route('/api/set_interval', methods=['POST'])
def set_interval():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    data = request.get_json()
    interval = data.get('interval', 60)
    
    # Validate interval
    if interval < 10 or interval > 3600:
        return jsonify({"error": "Interval must be between 10 and 3600 seconds"}), 400
    
    # Update generator
    generator.set_interval(interval)
    
    # Save to database for persistence
    try:
        conn, db_type = get_db()
        c = conn.cursor()
        
        # Ensure table exists
        c.execute("""
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Save interval
        if db_type == 'postgres':
            c.execute("""
                INSERT INTO system_settings (key, value, updated_at)
                VALUES ('verse_interval', %s, CURRENT_TIMESTAMP)
                ON CONFLICT (key) DO UPDATE SET
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
        
        conn.commit()
        conn.close()
        logger.info(f"Verse interval saved to database: {interval} seconds")
    except Exception as e:
        logger.error(f"Failed to save interval to DB: {e}")
    
    return jsonify({"success": True, "interval": generator.interval})

@app.route('/api/user_info')
def get_user_info():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("SELECT created_at, is_admin, is_banned, role, name FROM users WHERE id = %s", (session['user_id'],))
        else:
            c.execute("SELECT created_at, is_admin, is_banned, role, name FROM users WHERE id = ?", (session['user_id'],))
        
        row = c.fetchone()
        
        if row:
            try:
                return jsonify({
                    "created_at": row['created_at'],
                    "is_admin": bool(row['is_admin']),
                    "is_banned": bool(row['is_banned']),
                    "role": row['role'] or 'user',
                    "name": row.get('name') or session.get('user_name'),
                    "session_admin": session.get('is_admin', False)
                })
            except (TypeError, KeyError):
                return jsonify({
                    "created_at": row[0],
                    "is_admin": bool(row[1]),
                    "is_banned": bool(row[2]),
                    "role": row[3] if row[3] else 'user',
                    "name": row[4] if len(row) > 4 else session.get('user_name'),
                    "session_admin": session.get('is_admin', False)
                })
        return jsonify({"created_at": None, "is_admin": False, "is_banned": False, "role": "user", "name": session.get('user_name')})
    except Exception as e:
        logger.error(f"User info error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/user/update-name', methods=['POST'])
def update_user_name():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json() or {}
    new_name = (data.get('name') or '').strip()
    if len(new_name) < 2:
        return jsonify({"error": "Name must be at least 2 characters"}), 400
    if len(new_name) > 40:
        return jsonify({"error": "Name must be 40 characters or less"}), 400

    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    try:
        if db_type == 'postgres':
            c.execute("UPDATE users SET name = %s WHERE id = %s", (new_name, session['user_id']))
        else:
            c.execute("UPDATE users SET name = ? WHERE id = ?", (new_name, session['user_id']))
        conn.commit()
        session['user_name'] = new_name
        return jsonify({"success": True, "name": new_name})
    except Exception as e:
        logger.error(f"Update username error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/verify_role_code', methods=['POST'])
def verify_role_code():
    """Verify role code and assign appropriate role"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    data = request.get_json()
    code = data.get('code', '').strip().upper()
    selected_role = data.get('role', '').strip().lower()
    
    # Normalize role codes to uppercase for comparison
    host_code = str(ROLE_CODES.get('host', '')).strip().upper()
    mod_code = str(ROLE_CODES.get('mod', '')).strip().upper()
    co_owner_code = str(ROLE_CODES.get('co_owner', '')).strip().upper()
    owner_code = str(ROLE_CODES.get('owner', '')).strip().upper()
    
    # Debug log
    logger.info(f"Role code verification attempt. Selected role: '{selected_role}', Code entered: '{code}'")
    logger.info(f"Available codes - HOST: '{host_code}', MOD: '{mod_code}', CO_OWNER: '{co_owner_code}', OWNER: '{owner_code}'")
    
    # Validate the selected role and code match
    role = None
    code_valid = False
    
    if selected_role == 'host' and code == host_code:
        role = 'host'
        code_valid = True
    elif selected_role == 'mod' and code == mod_code:
        role = 'mod'
        code_valid = True
    elif selected_role == 'co_owner' and code == co_owner_code:
        role = 'co_owner'
        code_valid = True
    elif selected_role == 'owner' and code == owner_code:
        role = 'owner'
        code_valid = True
    
    if not code_valid:
        return jsonify({"success": False, "error": f"Invalid code for {selected_role.replace('_', ' ').title()} role."})
    
    if role:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        
        try:
            is_admin = 1 if role in ['owner', 'co_owner', 'mod', 'host'] else 0
            
            if db_type == 'postgres':
                c.execute("UPDATE users SET is_admin = %s, role = %s WHERE id = %s", (is_admin, role, session['user_id']))
            else:
                c.execute("UPDATE users SET is_admin = ?, role = ? WHERE id = ?", (is_admin, role, session['user_id']))
            
            conn.commit()
            
            session['is_admin'] = bool(is_admin)
            session['role'] = role
            log_action(session['user_id'], 'role_assigned', details={'role': role, 'code_used': True})
            
            logger.info(f"Role assigned successfully: {role} for user {session['user_id']}")
            
            role_display = role.replace('_', ' ').title()
            return jsonify({"success": True, "role": role, "role_display": role_display})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})
        finally:
            conn.close()

@app.route('/api/stats')
def get_stats():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    conn, db_type = get_db()
    c = conn.cursor()  # Use regular cursor for better compatibility
    
    try:
        # Ensure comments table has is_deleted column
        try:
            if db_type == 'postgres':
                c.execute("ALTER TABLE comments ADD COLUMN IF NOT EXISTS is_deleted INTEGER DEFAULT 0")
            else:
                c.execute("SELECT is_deleted FROM comments LIMIT 1")
        except:
            try:
                c.execute("ALTER TABLE comments ADD COLUMN is_deleted INTEGER DEFAULT 0")
            except:
                pass
        conn.commit()
        
        # Helper to get count safely
        def safe_count(query, params=None):
            try:
                if params:
                    c.execute(query, params)
                else:
                    c.execute(query)
                row = c.fetchone()
                return row[0] if row else 0
            except Exception as e:
                logger.error(f"Query failed: {query}, error: {e}")
                return 0
        
        if db_type == 'postgres':
            total = safe_count("SELECT COUNT(*) FROM verses")
            liked = safe_count("SELECT COUNT(*) FROM likes WHERE user_id = %s", (session['user_id'],))
            saved = safe_count("SELECT COUNT(*) FROM saves WHERE user_id = %s", (session['user_id'],))
            # Count all comments by this user
            comments = safe_count("SELECT COUNT(*) FROM comments WHERE user_id = %s", (session['user_id'],))
            # Also count community messages
            community = safe_count("SELECT COUNT(*) FROM community_messages WHERE user_id = %s", (session['user_id'],))
            replies = safe_count("SELECT COUNT(*) FROM comment_replies WHERE user_id = %s AND COALESCE(is_deleted, 0) = 0", (session['user_id'],))
        else:
            total = safe_count("SELECT COUNT(*) FROM verses")
            liked = safe_count("SELECT COUNT(*) FROM likes WHERE user_id = ?", (session['user_id'],))
            saved = safe_count("SELECT COUNT(*) FROM saves WHERE user_id = ?", (session['user_id'],))
            comments = safe_count("SELECT COUNT(*) FROM comments WHERE user_id = ?", (session['user_id'],))
            community = safe_count("SELECT COUNT(*) FROM community_messages WHERE user_id = ?", (session['user_id'],))
            replies = safe_count("SELECT COUNT(*) FROM comment_replies WHERE user_id = ? AND COALESCE(is_deleted, 0) = 0", (session['user_id'],))
        
        logger.info(f"Stats for user {session['user_id']}: verses={total}, liked={liked}, saved={saved}, comments={comments}, community={community}, replies={replies}")
        
        # Return total comments including community for the profile count
        total_comments = comments + community + replies
        
        return jsonify({"total_verses": total, "liked": liked, "saved": saved, "comments": total_comments, "replies": replies})
    except Exception as e:
        logger.error(f"Stats error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"total_verses": 0, "liked": 0, "saved": 0, "comments": 0})
    finally:
        conn.close()

@app.route('/api/daily_challenge')
def get_daily_challenge():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401

    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403

    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    today = datetime.now().date().isoformat()
    goal = 2

    try:
        if db_type == 'postgres':
            c.execute("""
                CREATE TABLE IF NOT EXISTS daily_actions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    verse_id INTEGER,
                    event_date TEXT NOT NULL,
                    timestamp TEXT,
                    UNIQUE(user_id, action, verse_id, event_date)
                )
            """)
            c.execute("""
                SELECT COUNT(*) AS count
                FROM daily_actions
                WHERE user_id = %s AND action = %s AND event_date = %s
            """, (session['user_id'], 'save', today))
            row = c.fetchone()
            progress = int(row['count'] if row and isinstance(row, dict) else (row[0] if row else 0))
        else:
            c.execute("""
                CREATE TABLE IF NOT EXISTS daily_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    verse_id INTEGER,
                    event_date TEXT NOT NULL,
                    timestamp TEXT,
                    UNIQUE(user_id, action, verse_id, event_date)
                )
            """)
            c.execute("""
                SELECT COUNT(*)
                FROM daily_actions
                WHERE user_id = ? AND action = ? AND event_date = ?
            """, (session['user_id'], 'save', today))
            row = c.fetchone()
            progress = int(row[0] if row else 0)

        conn.commit()
        progress = min(progress, goal)
        return jsonify({
            "id": "save2",
            "text": "Save 2 verses to your library",
            "goal": goal,
            "type": "save",
            "date": today,
            "progress": progress,
            "completed": progress >= goal
        })
    except Exception as e:
        logger.error(f"Daily challenge error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/debug/comments')
def debug_comments():
    """Debug endpoint to check comments data"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    conn, db_type = get_db()
    c = conn.cursor()
    
    try:
        # Get total comments count
        c.execute("SELECT COUNT(*) FROM comments")
        total_comments = c.fetchone()[0]
        
        # Get comments by current user
        if db_type == 'postgres':
            c.execute("SELECT COUNT(*) FROM comments WHERE user_id = %s", (session['user_id'],))
        else:
            c.execute("SELECT COUNT(*) FROM comments WHERE user_id = ?", (session['user_id'],))
        user_comments = c.fetchone()[0]
        
        # Get sample comments (last 5)
        if db_type == 'postgres':
            c.execute("SELECT id, user_id, verse_id, text, timestamp FROM comments ORDER BY timestamp DESC LIMIT 5")
        else:
            c.execute("SELECT id, user_id, verse_id, text, timestamp FROM comments ORDER BY timestamp DESC LIMIT 5")
        sample = c.fetchall()
        
        # Get table schema info
        if db_type == 'postgres':
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'comments'")
            columns = [row[0] for row in c.fetchall()]
        else:
            c.execute("PRAGMA table_info(comments)")
            columns = [row[1] for row in c.fetchall()]
        
        return jsonify({
            "total_comments": total_comments,
            "user_comments": user_comments,
            "current_user_id": session['user_id'],
            "sample_comments": [{"id": r[0], "user_id": r[1], "verse_id": r[2], "text": r[3][:50] if r[3] else None, "timestamp": r[4]} for r in sample],
            "table_columns": columns,
            "db_type": db_type
        })
    except Exception as e:
        logger.error(f"Debug error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/like', methods=['POST'])
def like_verse():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned", "message": "Account banned"}), 403
    
    data = request.get_json()
    verse_id = data.get('verse_id')
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("SELECT id FROM likes WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
            if c.fetchone():
                c.execute("DELETE FROM likes WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
                liked = False
            else:
                c.execute("INSERT INTO likes (user_id, verse_id, timestamp) VALUES (%s, %s, %s)",
                          (session['user_id'], verse_id, datetime.now().isoformat()))
                liked = True
        else:
            c.execute("SELECT id FROM likes WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
            if c.fetchone():
                c.execute("DELETE FROM likes WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
                liked = False
            else:
                c.execute("INSERT INTO likes (user_id, verse_id, timestamp) VALUES (?, ?, ?)",
                          (session['user_id'], verse_id, datetime.now().isoformat()))
                liked = True
        
        conn.commit()
        
        if liked:
            rec = generator.generate_smart_recommendation(session['user_id'])
            return jsonify({"liked": liked, "recommendation": rec})
        
        return jsonify({"liked": liked})
    except Exception as e:
        logger.error(f"Like error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/save', methods=['POST'])
def save_verse():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    data = request.get_json()
    verse_id = data.get('verse_id')
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        now = datetime.now().isoformat()
        today = datetime.now().date().isoformat()
        if db_type == 'postgres':
            c.execute("SELECT id FROM saves WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
            if c.fetchone():
                c.execute("DELETE FROM saves WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
                saved = False
            else:
                c.execute("INSERT INTO saves (user_id, verse_id, timestamp) VALUES (%s, %s, %s)",
                          (session['user_id'], verse_id, now))
                c.execute("""
                    INSERT INTO daily_actions (user_id, action, verse_id, event_date, timestamp)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (user_id, action, verse_id, event_date) DO NOTHING
                """, (session['user_id'], 'save', verse_id, today, now))
                saved = True
        else:
            c.execute("SELECT id FROM saves WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
            if c.fetchone():
                c.execute("DELETE FROM saves WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
                saved = False
            else:
                c.execute("INSERT INTO saves (user_id, verse_id, timestamp) VALUES (?, ?, ?)",
                          (session['user_id'], verse_id, now))
                c.execute("""
                    INSERT OR IGNORE INTO daily_actions (user_id, action, verse_id, event_date, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (session['user_id'], 'save', verse_id, today, now))
                saved = True
        
        conn.commit()
        return jsonify({"saved": saved})
    except Exception as e:
        logger.error(f"Save error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/library')
def get_library():
    if 'user_id' not in session:
        return jsonify({"liked": [], "saved": [], "collections": []})
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, l.timestamp as liked_at
                FROM verses v 
                JOIN likes l ON v.id = l.verse_id 
                WHERE l.user_id = %s 
                ORDER BY l.timestamp DESC
            """, (session['user_id'],))
            liked = [{"id": row['id'], "ref": row['reference'], "text": row['text'], "trans": row['translation'], 
                      "source": row['source'], "book": row['book'], "liked_at": row['liked_at'], "saved_at": None} for row in c.fetchall()]
            
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, s.timestamp as saved_at
                FROM verses v 
                JOIN saves s ON v.id = s.verse_id 
                WHERE s.user_id = %s 
                ORDER BY s.timestamp DESC
            """, (session['user_id'],))
            saved = [{"id": row['id'], "ref": row['reference'], "text": row['text'], "trans": row['translation'], 
                      "source": row['source'], "book": row['book'], "liked_at": None, "saved_at": row['saved_at']} for row in c.fetchall()]
            
            # GET COLLECTIONS
            c.execute("""
                SELECT c.id, c.name, c.color, COUNT(vc.verse_id) as count 
                FROM collections c
                LEFT JOIN verse_collections vc ON c.id = vc.collection_id
                WHERE c.user_id = %s
                GROUP BY c.id
            """, (session['user_id'],))
        else:
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, l.timestamp as liked_at
                FROM verses v 
                JOIN likes l ON v.id = l.verse_id 
                WHERE l.user_id = ? 
                ORDER BY l.timestamp DESC
            """, (session['user_id'],))
            rows = c.fetchall()
            liked = []
            for row in rows:
                try:
                    liked.append({"id": row['id'], "ref": row['reference'], "text": row['text'], "trans": row['translation'], 
                              "source": row['source'], "book": row['book'], "liked_at": row['liked_at'], "saved_at": None})
                except (TypeError, KeyError):
                    liked.append({"id": row[0], "ref": row[1], "text": row[2], "trans": row[3], 
                              "source": row[4], "book": row[6], "liked_at": row[7], "saved_at": None})
            
            c.execute("""
                SELECT v.id, v.reference, v.text, v.translation, v.source, v.book, s.timestamp as saved_at
                FROM verses v 
                JOIN saves s ON v.id = s.verse_id 
                WHERE s.user_id = ? 
                ORDER BY s.timestamp DESC
            """, (session['user_id'],))
            rows = c.fetchall()
            saved = []
            for row in rows:
                try:
                    saved.append({"id": row['id'], "ref": row['reference'], "text": row['text'], "trans": row['translation'], 
                              "source": row['source'], "book": row['book'], "liked_at": None, "saved_at": row['saved_at']})
                except (TypeError, KeyError):
                    saved.append({"id": row[0], "ref": row[1], "text": row[2], "trans": row[3], 
                              "source": row[4], "book": row[6], "liked_at": None, "saved_at": row[7]})
            
            # GET COLLECTIONS
            c.execute("""
                SELECT c.id, c.name, c.color, COUNT(vc.verse_id) as count 
                FROM collections c
                LEFT JOIN verse_collections vc ON c.id = vc.collection_id
                WHERE c.user_id = ?
                GROUP BY c.id
            """, (session['user_id'],))
        
        # Build collections list with verses
        collections = []
        for row in c.fetchall():
            try:
                col_id = row['id']
                col_name = row['name']
                col_color = row['color']
                col_count = row['count']
            except (TypeError, KeyError):
                col_id = row[0]
                col_name = row[1]
                col_color = row[2]
                col_count = row[3]
            
            if db_type == 'postgres':
                c.execute("""
                    SELECT v.id, v.reference, v.text FROM verses v
                    JOIN verse_collections vc ON v.id = vc.verse_id
                    WHERE vc.collection_id = %s
                """, (col_id,))
                verses = [{"id": v['id'], "ref": v['reference'], "text": v['text']} for v in c.fetchall()]
            else:
                c.execute("""
                    SELECT v.id, v.reference, v.text FROM verses v
                    JOIN verse_collections vc ON v.id = vc.verse_id
                    WHERE vc.collection_id = ?
                """, (col_id,))
                verses = []
                for v in c.fetchall():
                    try:
                        verses.append({"id": v['id'], "ref": v['reference'], "text": v['text']})
                    except (TypeError, KeyError):
                        verses.append({"id": v[0], "ref": v[1], "text": v[2]})
            
            collections.append({
                "id": col_id, "name": col_name, "color": col_color, 
                "count": col_count, "verses": verses
            })
        
        favorites = next((c for c in collections if (c.get("name") or "").lower() == "favorites"), None)
        return jsonify({
            "liked": liked,
            "saved": saved,
            "collections": collections,
            "liked_count": len(liked),
            "saved_count": len(saved),
            "favorites_count": len(favorites.get("verses", [])) if favorites else 0
        })
    except Exception as e:
        logger.error(f"Library error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/collections/add', methods=['POST'])
def add_to_collection():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    data = request.get_json()
    collection_id = data.get('collection_id')
    verse_id = data.get('verse_id')
    
    if not collection_id or not verse_id:
        return jsonify({"success": False, "error": "Missing collection_id or verse_id"}), 400
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        # Verify collection belongs to user
        if db_type == 'postgres':
            c.execute("SELECT user_id FROM collections WHERE id = %s", (collection_id,))
        else:
            c.execute("SELECT user_id FROM collections WHERE id = ?", (collection_id,))
        
        row = c.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Collection not found"}), 404
        
        try:
            owner_id = row['user_id'] if isinstance(row, dict) else row[0]
        except (TypeError, KeyError):
            owner_id = row[0]
        
        if owner_id != session['user_id']:
            return jsonify({"success": False, "error": "Not your collection"}), 403
        
        # Add verse to collection
        if db_type == 'postgres':
            c.execute("INSERT INTO verse_collections (collection_id, verse_id) VALUES (%s, %s)",
                      (collection_id, verse_id))
        else:
            c.execute("INSERT INTO verse_collections (collection_id, verse_id) VALUES (?, ?)",
                      (collection_id, verse_id))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Add to collection error: {e}")
        # Likely already exists
        return jsonify({"success": False, "error": "Already in collection or database error"})
    finally:
        conn.close()

@app.route('/api/collections/create', methods=['POST'])
def create_collection():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    data = request.get_json()
    name = data.get('name')
    color = data.get('color', '#0A84FF')
    
    if not name:
        return jsonify({"error": "Name required"}), 400
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("INSERT INTO collections (user_id, name, color, created_at) VALUES (%s, %s, %s, %s) RETURNING id",
                      (session['user_id'], name, color, datetime.now().isoformat()))
            new_id = c.fetchone()['id']
        else:
            c.execute("INSERT INTO collections (user_id, name, color, created_at) VALUES (?, ?, ?, ?)",
                      (session['user_id'], name, color, datetime.now().isoformat()))
            new_id = c.lastrowid
        
        conn.commit()
        return jsonify({"id": new_id, "name": name, "color": color, "count": 0, "verses": []})
    except Exception as e:
        logger.error(f"Create collection error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/recommendations')
def get_recommendations():
    if 'user_id' not in session:
        return jsonify([])
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    rec = generator.generate_smart_recommendation(session['user_id'])
    if rec:
        return jsonify({"recommendations": [rec]})
    return jsonify({"recommendations": []})

@app.route('/api/generate-recommendation', methods=['POST'])
def generate_rec():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned"}), 403
    
    rec = generator.generate_smart_recommendation(session['user_id'])
    if rec:
        return jsonify({"success": True, "recommendation": rec})
    return jsonify({"success": False})

@app.route('/api/comments/<int:verse_id>')
def get_comments(verse_id):
    logger.info(f"[DEBUG] get_comments called for verse_id={verse_id}")
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        # Ensure table exists
        if db_type == 'postgres':
            c.execute("""
                CREATE TABLE IF NOT EXISTS comments (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    verse_id INTEGER,
                    text TEXT,
                    timestamp TIMESTAMP,
                    google_name TEXT,
                    google_picture TEXT,
                    is_deleted INTEGER DEFAULT 0
                )
            """)
        else:
            c.execute("""
                CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    verse_id INTEGER,
                    text TEXT,
                    timestamp TIMESTAMP,
                    google_name TEXT,
                    google_picture TEXT,
                    is_deleted INTEGER DEFAULT 0
                )
            """)
        conn.commit()
        
        # Count total comments first
        if db_type == 'postgres':
            c.execute("SELECT COUNT(*) as count FROM comments")
        else:
            c.execute("SELECT COUNT(*) as count FROM comments")
        count_row = c.fetchone()
        try:
            total_count = count_row['count'] if isinstance(count_row, dict) else count_row[0]
        except:
            total_count = 0
        logger.info(f"[DEBUG] Total comments in database: {total_count}")
        
        ensure_comment_social_tables(c, db_type)
        conn.commit()

        # Query comments for this verse
        if db_type == 'postgres':
            c.execute("""
                SELECT id, user_id, text, timestamp, google_name
                FROM comments
                WHERE verse_id = %s AND COALESCE(is_deleted, 0) = 0
                ORDER BY timestamp DESC
            """, (verse_id,))
        else:
            c.execute("""
                SELECT id, user_id, text, timestamp, google_name
                FROM comments
                WHERE verse_id = ? AND COALESCE(is_deleted, 0) = 0
                ORDER BY timestamp DESC
            """, (verse_id,))
        
        rows = c.fetchall()
        
        comments = []
        for row in rows:
            try:
                comment_id = row['id']
                user_id = row['user_id']
                text = row['text']
                timestamp = row['timestamp']
                google_name = row['google_name']
            except (TypeError, KeyError):
                comment_id = row[0]
                user_id = row[1]
                text = row[2]
                timestamp = row[3]
                google_name = row[4]
            
            # Get user info if available
            user_name = google_name or "Anonymous"
            user_picture = ""
            user_role = "user"
            
            if user_id:
                try:
                    if db_type == 'postgres':
                        c.execute("SELECT name, picture, role FROM users WHERE id = %s", (user_id,))
                    else:
                        c.execute("SELECT name, picture, role FROM users WHERE id = ?", (user_id,))
                    user_row = c.fetchone()
                    if user_row:
                        try:
                            user_name = user_row['name'] or google_name or "Anonymous"
                            user_picture = user_row['picture'] or ""
                            user_role = user_row.get('role') or "user"
                        except (TypeError, KeyError):
                            user_name = user_row[0] or google_name or "Anonymous"
                            user_picture = user_row[1] or ""
                            user_role = user_row[2] if len(user_row) > 2 and user_row[2] else "user"
                except Exception as user_err:
                    logger.error(f"Error getting user info: {user_err}")
            
            replies = get_replies_for_parent(c, db_type, "comment", comment_id)
            comments.append({
                "id": comment_id,
                "text": text or "",
                "timestamp": timestamp,
                "user_name": user_name,
                "user_picture": user_picture,
                "user_id": user_id,
                "user_role": user_role,
                "reactions": get_reaction_counts(c, db_type, "comment", comment_id),
                "replies": replies,
                "reply_count": len(replies)
            })
        
        return jsonify(comments)
    except Exception as e:
        logger.error(f"Get comments error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

def check_comment_restriction(user_id):
    """Check if user is restricted from commenting. Returns (is_restricted, reason, expires_at)"""
    try:
        logger.info(f"[DEBUG] check_comment_restriction called for user_id={user_id}")
        
        conn, db_type = get_db()
        c = conn.cursor()
        
        logger.info(f"[DEBUG] db_type={db_type}")
        
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
        conn.commit()
        
        # Check for active restriction
        now = datetime.now().isoformat()
        logger.info(f"[DEBUG] Checking restriction: user_id={user_id}, now={now}")
        
        if db_type == 'postgres':
            c.execute("SELECT reason, expires_at FROM comment_restrictions WHERE user_id = %s AND expires_at > %s",
                     (user_id, now))
        else:
            c.execute("SELECT reason, expires_at FROM comment_restrictions WHERE user_id = ? AND expires_at > ?",
                     (user_id, now))
        row = c.fetchone()
        conn.close()
        
        logger.info(f"[DEBUG] Restriction query result: {row}")
        
        if row:
            logger.info(f"[DEBUG] User {user_id} is RESTRICTED: reason={row[0]}, expires={row[1]}")
            return (True, row[0], row[1])
        
        logger.info(f"[DEBUG] User {user_id} is NOT restricted")
        return (False, None, None)
    except Exception as e:
        logger.error(f"Check restriction error: {e}")
        import traceback
        traceback.print_exc()
        return (False, None, None)

@app.route('/api/comments', methods=['POST'])
def post_comment():
    logger.info(f"[DEBUG] post_comment called, user_id={session.get('user_id')}")
    
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned", "message": "Account banned"}), 403
    
    # Check for comment restriction
    is_restricted, reason, expires_at = check_comment_restriction(session['user_id'])
    if is_restricted:
        expires_str = datetime.fromisoformat(expires_at).strftime("%Y-%m-%d %H:%M") if expires_at else "soon"
        return jsonify({
            "error": "restricted", 
            "message": f"You have been restricted from commenting due to {reason} for 1-24hrs",
            "reason": reason,
            "expires_at": expires_str
        }), 403
    
    data = request.get_json()
    verse_id = data.get('verse_id')
    text = data.get('text', '').strip()
    
    logger.info(f"[DEBUG] Posting comment: verse_id={verse_id}, text={text[:20]}...")
    
    if not text:
        return jsonify({"error": "Empty comment"}), 400
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    logger.info(f"[DEBUG] Using db_type={db_type}")
    
    try:
        # Ensure comments table exists
        if db_type == 'postgres':
            c.execute("""
                CREATE TABLE IF NOT EXISTS comments (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    verse_id INTEGER,
                    text TEXT,
                    timestamp TIMESTAMP,
                    google_name TEXT,
                    google_picture TEXT,
                    is_deleted INTEGER DEFAULT 0
                )
            """)
        else:
            c.execute("""
                CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    verse_id INTEGER,
                    text TEXT,
                    timestamp TIMESTAMP,
                    google_name TEXT,
                    google_picture TEXT,
                    is_deleted INTEGER DEFAULT 0
                )
            """)
        conn.commit()
        
        if db_type == 'postgres':
            c.execute("INSERT INTO comments (user_id, verse_id, text, timestamp, google_name, google_picture) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                      (session['user_id'], verse_id, text, datetime.now().isoformat(), 
                       session.get('user_name'), session.get('user_picture')))
            result = c.fetchone()
            comment_id = result['id'] if result else None
        else:
            c.execute("INSERT INTO comments (user_id, verse_id, text, timestamp, google_name, google_picture) VALUES (?, ?, ?, ?, ?, ?)",
                      (session['user_id'], verse_id, text, datetime.now().isoformat(), 
                       session.get('user_name'), session.get('user_picture')))
            comment_id = c.lastrowid
        
        conn.commit()
        logger.info(f"[DEBUG] Comment posted successfully, id={comment_id}")
        return jsonify({"success": True, "id": comment_id})
    except Exception as e:
        logger.error(f"[DEBUG] Post comment error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/community')
def get_community_messages():
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        ensure_comment_social_tables(c, db_type)
        conn.commit()

        if db_type == 'postgres':
            c.execute("""
                SELECT
                    cm.id, cm.user_id, cm.text, cm.timestamp, cm.google_name, cm.google_picture,
                    u.name, u.picture, u.role
                FROM community_messages cm
                LEFT JOIN users u ON cm.user_id = u.id
                ORDER BY timestamp DESC
                LIMIT 100
            """)
        else:
            c.execute("""
                SELECT
                    cm.id, cm.user_id, cm.text, cm.timestamp, cm.google_name, cm.google_picture,
                    u.name, u.picture, u.role
                FROM community_messages cm
                LEFT JOIN users u ON cm.user_id = u.id
                ORDER BY timestamp DESC
                LIMIT 100
            """)
        
        rows = c.fetchall()
        
        messages = []
        for row in rows:
            try:
                msg_id = row['id']
                user_id = row['user_id']
                text = row['text']
                timestamp = row['timestamp']
                google_name = row['google_name']
                google_picture = row['google_picture']
                db_name = row.get('name')
                db_picture = row.get('picture')
                db_role = row.get('role')
            except (TypeError, KeyError):
                msg_id = row[0]
                user_id = row[1]
                text = row[2]
                timestamp = row[3]
                google_name = row[4]
                google_picture = row[5]
                db_name = row[6] if len(row) > 6 else None
                db_picture = row[7] if len(row) > 7 else None
                db_role = row[8] if len(row) > 8 else None
            
            user_name = db_name or google_name or "Anonymous"
            user_picture = db_picture or google_picture or ""
            
            replies = get_replies_for_parent(c, db_type, "community", msg_id)
            messages.append({
                "id": msg_id,
                "text": text or "",
                "timestamp": timestamp,
                "user_name": user_name,
                "user_picture": user_picture,
                "user_id": user_id,
                "user_role": db_role or "user",
                "reactions": get_reaction_counts(c, db_type, "community", msg_id),
                "replies": replies,
                "reply_count": len(replies)
            })
        
        return jsonify(messages)
    except Exception as e:
        logger.error(f"Get community error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/community', methods=['POST'])
def post_community_message():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned", "message": "Account banned"}), 403
    
    # Check for comment restriction
    is_restricted, reason, expires_at = check_comment_restriction(session['user_id'])
    if is_restricted:
        expires_str = datetime.fromisoformat(expires_at).strftime("%Y-%m-%d %H:%M") if expires_at else "soon"
        return jsonify({
            "error": "restricted", 
            "message": f"You have been restricted from commenting due to {reason} for 1-24hrs",
            "reason": reason,
            "expires_at": expires_str
        }), 403
    
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({"error": "Empty message"}), 400
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("INSERT INTO community_messages (user_id, text, timestamp, google_name, google_picture) VALUES (%s, %s, %s, %s, %s)",
                      (session['user_id'], text, datetime.now().isoformat(), 
                       session.get('user_name'), session.get('user_picture')))
        else:
            c.execute("INSERT INTO community_messages (user_id, text, timestamp, google_name, google_picture) VALUES (?, ?, ?, ?, ?)",
                      (session['user_id'], text, datetime.now().isoformat(), 
                       session.get('user_name'), session.get('user_picture')))
        
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Post community error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/comments/reaction', methods=['POST'])
def add_comment_reaction():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json() or {}
    item_id = data.get('item_id')
    item_type = str(data.get('item_type', 'comment')).strip().lower()
    reaction = str(data.get('reaction', '')).strip().lower()

    if item_type not in ('comment', 'community'):
        return jsonify({"error": "Invalid item_type"}), 400
    if reaction not in ('heart', 'pray', 'cross'):
        return jsonify({"error": "Invalid reaction"}), 400
    if not item_id:
        return jsonify({"error": "item_id required"}), 400

    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    try:
        ensure_comment_social_tables(c, db_type)
        now = datetime.now().isoformat()

        if db_type == 'postgres':
            c.execute("""
                SELECT id FROM comment_reactions
                WHERE item_type = %s AND item_id = %s AND user_id = %s AND reaction = %s
            """, (item_type, item_id, session['user_id'], reaction))
        else:
            c.execute("""
                SELECT id FROM comment_reactions
                WHERE item_type = ? AND item_id = ? AND user_id = ? AND reaction = ?
            """, (item_type, item_id, session['user_id'], reaction))
        exists = c.fetchone()

        if exists:
            if db_type == 'postgres':
                c.execute("""
                    DELETE FROM comment_reactions
                    WHERE item_type = %s AND item_id = %s AND user_id = %s AND reaction = %s
                """, (item_type, item_id, session['user_id'], reaction))
            else:
                c.execute("""
                    DELETE FROM comment_reactions
                    WHERE item_type = ? AND item_id = ? AND user_id = ? AND reaction = ?
                """, (item_type, item_id, session['user_id'], reaction))
            active = False
        else:
            if db_type == 'postgres':
                c.execute("""
                    INSERT INTO comment_reactions (item_type, item_id, user_id, reaction, timestamp)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (item_type, item_id, user_id, reaction) DO NOTHING
                """, (item_type, item_id, session['user_id'], reaction, now))
            else:
                c.execute("""
                    INSERT OR IGNORE INTO comment_reactions (item_type, item_id, user_id, reaction, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (item_type, item_id, session['user_id'], reaction, now))
            active = True

        conn.commit()
        counts = get_reaction_counts(c, db_type, item_type, int(item_id))
        return jsonify({"success": True, "active": active, "reactions": counts})
    except Exception as e:
        logger.error(f"Add reaction error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/comments/replies', methods=['POST'])
def post_comment_reply():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json() or {}
    parent_type = str(data.get('parent_type', 'comment')).strip().lower()
    parent_id = data.get('parent_id')
    text = str(data.get('text', '')).strip()

    if parent_type not in ('comment', 'community'):
        return jsonify({"error": "Invalid parent_type"}), 400
    if not parent_id:
        return jsonify({"error": "parent_id required"}), 400
    if not text:
        return jsonify({"error": "Empty reply"}), 400

    is_banned, _, _ = check_ban_status(session['user_id'])
    if is_banned:
        return jsonify({"error": "banned", "message": "Account banned"}), 403
    is_restricted, reason, expires_at = check_comment_restriction(session['user_id'])
    if is_restricted:
        expires_str = datetime.fromisoformat(expires_at).strftime("%Y-%m-%d %H:%M") if expires_at else "soon"
        return jsonify({
            "error": "restricted",
            "message": f"You have been restricted from commenting due to {reason} for 1-24hrs",
            "reason": reason,
            "expires_at": expires_str
        }), 403

    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    try:
        ensure_comment_social_tables(c, db_type)
        now = datetime.now().isoformat()
        if db_type == 'postgres':
            c.execute("""
                INSERT INTO comment_replies (parent_type, parent_id, user_id, text, timestamp, google_name, google_picture)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (parent_type, parent_id, session['user_id'], text, now, session.get('user_name'), session.get('user_picture')))
        else:
            c.execute("""
                INSERT INTO comment_replies (parent_type, parent_id, user_id, text, timestamp, google_name, google_picture)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (parent_type, parent_id, session['user_id'], text, now, session.get('user_name'), session.get('user_picture')))
        conn.commit()
        replies = get_replies_for_parent(c, db_type, parent_type, int(parent_id))
        return jsonify({"success": True, "replies": replies, "reply_count": len(replies)})
    except Exception as e:
        logger.error(f"Post reply error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/check_like/<int:verse_id>')
def check_like(verse_id):
    if 'user_id' not in session:
        return jsonify({"liked": False})
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("SELECT id FROM likes WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
        else:
            c.execute("SELECT id FROM likes WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
        
        liked = c.fetchone() is not None
        return jsonify({"liked": liked})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/check_save/<int:verse_id>')
def check_save(verse_id):
    if 'user_id' not in session:
        return jsonify({"saved": False})
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("SELECT id FROM saves WHERE user_id = %s AND verse_id = %s", (session['user_id'], verse_id))
        else:
            c.execute("SELECT id FROM saves WHERE user_id = ? AND verse_id = ?", (session['user_id'], verse_id))
        
        saved = c.fetchone() is not None
        return jsonify({"saved": saved})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# Admin delete comment/community endpoints (needed for frontend)
@app.route('/api/admin/delete_comment/<int:comment_id>', methods=['DELETE'])
def delete_comment_api(comment_id):
    """Delete a comment (admin only)"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    # Check if user is admin
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        # Soft delete by setting is_deleted = 1
        if db_type == 'postgres':
            c.execute("UPDATE comments SET is_deleted = 1 WHERE id = %s", (comment_id,))
        else:
            c.execute("UPDATE comments SET is_deleted = 1 WHERE id = ?", (comment_id,))
        conn.commit()
        
        # Log the action
        log_action(session.get('user_id'), 'DELETE_COMMENT', comment_id, {'type': 'comment'})
        
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Delete comment error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/admin/delete_community/<int:message_id>', methods=['DELETE'])
def delete_community_api(message_id):
    """Delete a community message (admin only)"""
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    
    # Check if user is admin
    if not session.get('is_admin'):
        return jsonify({"error": "Admin required"}), 403
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        # Hard delete community messages (no is_deleted column)
        if db_type == 'postgres':
            c.execute("DELETE FROM community_messages WHERE id = %s", (message_id,))
        else:
            c.execute("DELETE FROM community_messages WHERE id = ?", (message_id,))
        conn.commit()
        
        # Log the action
        log_action(session.get('user_id'), 'DELETE_COMMENT', message_id, {'type': 'community'})
        
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Delete community message error: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/liked_verses')
def get_liked_verses():
    """Get all verses the user has liked with book info"""
    if 'user_id' not in session:
        return jsonify([]), 401
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("""
                SELECT v.id, v.reference, v.book 
                FROM verses v 
                JOIN likes l ON v.id = l.verse_id 
                WHERE l.user_id = %s
                ORDER BY l.timestamp DESC
            """, (session['user_id'],))
        else:
            c.execute("""
                SELECT v.id, v.reference, v.book 
                FROM verses v 
                JOIN likes l ON v.id = l.verse_id 
                WHERE l.user_id = ?
                ORDER BY l.timestamp DESC
            """, (session['user_id'],))
        
        rows = c.fetchall()
        verses = []
        for row in rows:
            try:
                verses.append({
                    "id": row['id'],
                    "ref": row['reference'],
                    "book": row['book']
                })
            except (TypeError, KeyError):
                verses.append({
                    "id": row[0],
                    "ref": row[1],
                    "book": row[2]
                })
        return jsonify(verses)
    except Exception as e:
        logger.error(f"Liked verses error: {e}")
        return jsonify([]), 500
    finally:
        conn.close()


@app.route('/api/saved_verses')
def get_saved_verses():
    """Get all verses the user has saved with book info"""
    if 'user_id' not in session:
        return jsonify([]), 401
    
    conn, db_type = get_db()
    c = get_cursor(conn, db_type)
    
    try:
        if db_type == 'postgres':
            c.execute("""
                SELECT v.id, v.reference, v.book 
                FROM verses v 
                JOIN saves s ON v.id = s.verse_id 
                WHERE s.user_id = %s
                ORDER BY s.timestamp DESC
            """, (session['user_id'],))
        else:
            c.execute("""
                SELECT v.id, v.reference, v.book 
                FROM verses v 
                JOIN saves s ON v.id = s.verse_id 
                WHERE s.user_id = ?
                ORDER BY s.timestamp DESC
            """, (session['user_id'],))
        
        rows = c.fetchall()
        verses = []
        for row in rows:
            try:
                verses.append({
                    "id": row['id'],
                    "ref": row['reference'],
                    "book": row['book']
                })
            except (TypeError, KeyError):
                verses.append({
                    "id": row[0],
                    "ref": row[1],
                    "book": row[2]
                })
        return jsonify(verses)
    except Exception as e:
        logger.error(f"Saved verses error: {e}")
        return jsonify([]), 500
    finally:
        conn.close()

@app.route('/api/presence/ping', methods=['POST'])
def presence_ping():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    conn = None
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_presence (
                user_id INTEGER PRIMARY KEY,
                last_seen TEXT,
                last_path TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        now_iso = datetime.now().isoformat()
        path = request.json.get('path') if request.is_json else request.path
        if db_type == 'postgres':
            c.execute("""
                INSERT INTO user_presence (user_id, last_seen, last_path, updated_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (user_id) DO UPDATE SET
                    last_seen = EXCLUDED.last_seen,
                    last_path = EXCLUDED.last_path,
                    updated_at = EXCLUDED.updated_at
            """, (session['user_id'], now_iso, path, now_iso))
        else:
            c.execute("""
                INSERT INTO user_presence (user_id, last_seen, last_path, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    last_path = excluded.last_path,
                    updated_at = excluded.updated_at
            """, (session['user_id'], now_iso, path, now_iso))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Presence ping error: {e}")
        if conn:
            try:
                conn.close()
            except:
                pass
        return jsonify({"error": str(e)}), 500

@app.route('/api/notifications')
def get_notifications():
    if 'user_id' not in session:
        return jsonify([]), 401
    conn = None
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        if db_type == 'postgres':
            c.execute("""
                CREATE TABLE IF NOT EXISTS user_notifications (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    title TEXT,
                    message TEXT,
                    notif_type TEXT DEFAULT 'announcement',
                    source TEXT DEFAULT 'admin',
                    is_read INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    sent_at TIMESTAMP
                )
            """)
        else:
            c.execute("""
                CREATE TABLE IF NOT EXISTS user_notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    title TEXT,
                    message TEXT,
                    notif_type TEXT DEFAULT 'announcement',
                    source TEXT DEFAULT 'admin',
                    is_read INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    sent_at TEXT
                )
            """)
        if db_type == 'postgres':
            c.execute("""
                SELECT id, title, message, notif_type, source, is_read, created_at
                FROM user_notifications
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT 50
            """, (session['user_id'],))
        else:
            c.execute("""
                SELECT id, title, message, notif_type, source, is_read, created_at
                FROM user_notifications
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 50
            """, (session['user_id'],))
        rows = c.fetchall()
        conn.close()
        out = []
        for row in rows:
            if hasattr(row, 'keys'):
                out.append({
                    "id": row.get('id'),
                    "title": row.get('title') or 'Notification',
                    "message": row.get('message') or '',
                    "type": row.get('notif_type') or 'announcement',
                    "source": row.get('source') or 'admin',
                    "is_read": bool(row.get('is_read') or 0),
                    "created_at": row.get('created_at')
                })
            else:
                out.append({
                    "id": row[0],
                    "title": row[1] or 'Notification',
                    "message": row[2] or '',
                    "type": row[3] or 'announcement',
                    "source": row[4] or 'admin',
                    "is_read": bool(row[5] or 0),
                    "created_at": row[6]
                })
        return jsonify(out)
    except Exception as e:
        logger.error(f"Get notifications error: {e}")
        if conn:
            try:
                conn.close()
            except:
                pass
        return jsonify([]), 500

@app.route('/api/notifications/read', methods=['POST'])
def mark_notifications_read():
    if 'user_id' not in session:
        return jsonify({"error": "Not logged in"}), 401
    conn = None
    try:
        conn, db_type = get_db()
        c = get_cursor(conn, db_type)
        if db_type == 'postgres':
            c.execute("""
                CREATE TABLE IF NOT EXISTS user_notifications (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    title TEXT,
                    message TEXT,
                    notif_type TEXT DEFAULT 'announcement',
                    source TEXT DEFAULT 'admin',
                    is_read INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    sent_at TIMESTAMP
                )
            """)
        else:
            c.execute("""
                CREATE TABLE IF NOT EXISTS user_notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    title TEXT,
                    message TEXT,
                    notif_type TEXT DEFAULT 'announcement',
                    source TEXT DEFAULT 'admin',
                    is_read INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    sent_at TEXT
                )
            """)
        if db_type == 'postgres':
            c.execute("UPDATE user_notifications SET is_read = 1 WHERE user_id = %s", (session['user_id'],))
        else:
            c.execute("UPDATE user_notifications SET is_read = 1 WHERE user_id = ?", (session['user_id'],))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Mark notifications read error: {e}")
        if conn:
            try:
                conn.close()
            except:
                pass
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
