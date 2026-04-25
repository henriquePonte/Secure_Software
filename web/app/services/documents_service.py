def get_documents(cur, owner_id):
    cur.execute("""
                SELECT id,title,filename,uploaded_at
                FROM documents
                WHERE owner_id=%s
                ORDER BY uploaded_at DESC
                """, (owner_id,))
    return cur.fetchall()