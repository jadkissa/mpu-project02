import os
import psycopg2
import psycopg2.extras

DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "mpu_db"),
    "user": os.getenv("DB_USER", "mpu"),
    "password": os.getenv("DB_PASSWORD", "123"),
    "host": os.getenv("DB_HOST", "postgres"),
    "port": int(os.getenv("DB_PORT", 5432))
}

def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def query(sql: str, params=None):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, params or ())
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]