from ..extensions import get_db
import psycopg2.extras


def get_user_documents(owner_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
                SELECT id, title, filename, uploaded_at
                FROM documents
                WHERE owner_id = %s
                ORDER BY uploaded_at DESC
                """, (owner_id,))

    docs = cur.fetchall()

    cur.close()
    conn.close()

    return docs


def create_document(user_id, title, filename):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
                INSERT INTO documents (owner_id, title, filename)
                VALUES (%s, %s, %s)
                """, (user_id, title, filename))

    conn.commit()
    cur.close()
    conn.close()


def get_document_by_id(document_id):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
                SELECT id, title, filename, uploaded_at, owner_id
                FROM documents
                WHERE id = %s
                """, (document_id,))

    doc = cur.fetchone()

    cur.close()
    conn.close()

    return doc