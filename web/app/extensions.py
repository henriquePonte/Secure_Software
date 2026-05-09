import os
import time
import psycopg2

def get_db():
    database_url = os.getenv("DATABASE_URL")

    for _ in range(10):
        try:
            if database_url:
                return psycopg2.connect(database_url)

            return psycopg2.connect(
                host=os.getenv("DB_HOST"),
                port=os.getenv("DB_PORT"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                dbname=os.getenv("DB_NAME"),
            )
        except Exception:
            time.sleep(1)

    raise RuntimeError("Database not available")