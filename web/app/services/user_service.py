from ..extensions import get_db
import psycopg2.extras

def get_all_users():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
                SELECT id, username
                FROM users
                WHERE is_disabled = FALSE
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