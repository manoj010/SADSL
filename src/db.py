import sqlite3

DB_NAME = "sadsl.db"

def get_connection():
    return sqlite3.connect(DB_NAME)


def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        create table if not exists suspicious_events (
            id integer primary key autoincrement,
            ip text not null,
            timestamp text not null,
            rule text not null,
            severity text not null,
            line_no integer not null
        )
    """)

    conn.commit()
    conn.close()


def insert_suspicious_event(event: dict):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        insert into suspicious_events
        (ip, timestamp, rule, severity, line_no)
        values (?, ?, ?, ?, ?)
    """, (
        event["ip"],
        event["timestamp"],
        event["rule"],
        event["severity"],
        event["line_no"]
    ))

    conn.commit()
    conn.close()
