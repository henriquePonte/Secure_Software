from . import utils

def get_user_by_username(cur, username):
    query, params = utils.prepare_query(
        "SELECT id, username, password, is_disabled FROM users WHERE username = %s",
        username,
    )
    cur.execute(query, params)
    return cur.fetchone()
