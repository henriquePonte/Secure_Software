from ..extensions import get_db
import psycopg2.extras
from .. import utils

def get_all_users():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
                SELECT id, username, is_disabled
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