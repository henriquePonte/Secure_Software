from ..extensions import get_db
import psycopg2.extras
from .. import utils
from threading import Lock

_ACCOUNT_RECOVERY_SCHEMA_LOCK = Lock()
_ACCOUNT_RECOVERY_SCHEMA_READY = False


def ensure_account_recovery_columns():
    global _ACCOUNT_RECOVERY_SCHEMA_READY

    if _ACCOUNT_RECOVERY_SCHEMA_READY:
        return

    with _ACCOUNT_RECOVERY_SCHEMA_LOCK:
        if _ACCOUNT_RECOVERY_SCHEMA_READY:
            return

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
                    ALTER TABLE users
                    ADD COLUMN IF NOT EXISTS session_revoked_at TIMESTAMP DEFAULT NULL
                    """)
        cur.execute("""
                    ALTER TABLE users
                    ADD COLUMN IF NOT EXISTS password_reset_required BOOLEAN DEFAULT FALSE
                    """)

        conn.commit()
        cur.close()
        conn.close()

        _ACCOUNT_RECOVERY_SCHEMA_READY = True

def get_all_users():
    ensure_account_recovery_columns()

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
                SELECT id, username, is_disabled, session_revoked_at,
                       password_reset_required
                FROM users
                ORDER BY username
                """)

    users = cur.fetchall()

    cur.close()
    conn.close()

    return users

def get_all_users_for_sharing(current_user_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
                SELECT id, username
                FROM users
                WHERE is_disabled = FALSE
                  AND id != %s
                  AND username != 'admin'
                ORDER BY username
                """, (current_user_id,))

    users = cur.fetchall()

    cur.close()
    conn.close()

    return users

def get_user_by_username(cur, username):
    sql = "SELECT id, username, password, is_disabled FROM users WHERE username = %s"
    params = (username,)

    sql, params = utils.prepare_query(sql, params)

    cur.execute(sql, params)
    return cur.fetchone()

def set_user_disabled(user_id, disabled: bool):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
                UPDATE users
                SET is_disabled = %s
                WHERE id = %s
                """, (disabled, user_id))

    conn.commit()
    cur.close()
    conn.close()


def get_user_session_revoked_at(user_id):
    ensure_account_recovery_columns()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
                SELECT session_revoked_at
                FROM users
                WHERE id = %s
                """, (user_id,))

    row = cur.fetchone()

    cur.close()
    conn.close()

    return row[0] if row else None


def revoke_user_sessions(user_id):
    ensure_account_recovery_columns()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
                UPDATE users
                SET session_revoked_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """, (user_id,))

    affected_rows = cur.rowcount

    conn.commit()
    cur.close()
    conn.close()

    return affected_rows > 0


def is_password_reset_required(user_id):
    ensure_account_recovery_columns()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
                SELECT password_reset_required
                FROM users
                WHERE id = %s
                """, (user_id,))

    row = cur.fetchone()

    cur.close()
    conn.close()

    return bool(row[0]) if row else False


def force_user_password_reset(user_id, temporary_password_hash):
    ensure_account_recovery_columns()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
                UPDATE users
                SET password = %s,
                    password_reset_required = TRUE,
                    session_revoked_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """, (temporary_password_hash, user_id))

    affected_rows = cur.rowcount

    conn.commit()
    cur.close()
    conn.close()

    return affected_rows > 0


def complete_password_reset(user_id, new_password_hash):
    ensure_account_recovery_columns()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
                UPDATE users
                SET password = %s,
                    password_reset_required = FALSE,
                    session_revoked_at = CURRENT_TIMESTAMP
                WHERE id = %s
                  AND password_reset_required = TRUE
                """, (new_password_hash, user_id))

    affected_rows = cur.rowcount

    conn.commit()
    cur.close()
    conn.close()

    return affected_rows > 0
