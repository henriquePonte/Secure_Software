from ..extensions import get_db


def user_can_access_document(user_id, document_id):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
                SELECT 1
                FROM documents d
                         LEFT JOIN document_shares ds
                                   ON ds.document_id = d.id
                WHERE d.id = %s
                  AND (d.owner_id = %s OR ds.shared_with = %s)
                """, (document_id, user_id, user_id))

    result = cur.fetchone()

    cur.close()
    conn.close()

    return result is not None