import sqlite3, subprocess

def get_user(db, uid):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    # taint: uid flows into a string-formatted SQL query (SQLi)
    cur.execute("SELECT * FROM users WHERE id = '%s'" % uid)
    return cur.fetchall()

def run(cmd):
    # command injection: user cmd into shell
    return subprocess.check_output(cmd, shell=True)
