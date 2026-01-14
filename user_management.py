import sqlite3 as sql
import time
import random
import bcrypt
from cryptography.fernet import Fernet
import os
import html
import threading

visitor_lock = threading.Lock()
feedback_lock = threading.Lock()

fernet = Fernet(os.environ["FERNET_KEY"])


def encrypt(data: str) -> bytes:
    return fernet.encrypt(data.encode())


def decrypt(data: bytes) -> str:
    return fernet.decrypt(data).decode()


def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Hash password
    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    encrypted_dob = encrypt(DoB)
    encrypted_username = encrypt(username)

    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth) VALUES (?, ?, ?)",
        (encrypted_username, hashed_pw, encrypted_dob),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Get user by username
    cur.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = cur.fetchone()

    if row is None:
        con.close()
        return False

    stored_hash = row[0]

    # Check password
    if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        # Visitor counter now inputting into database instead of file
        try:
            with visitor_lock:
                cur.execute(
                    "CREATE TABLE IF NOT EXISTS visitor_counter (id INTEGER PRIMARY KEY CHECK (id=1), count INTEGER NOT NULL)"
                )
                cur.execute("UPDATE visitor_counter SET count = count + 1 WHERE id = 1")
                if cur.rowcount == 0:
                    cur.execute("INSERT INTO visitor_counter (id, count) VALUES (1, 1)")
                con.commit()
        except Exception:
            con.rollback()

        # time.sleep(random.randint(80, 90) / 1000)
        con.close()
        return True
    else:
        con.close()
        return False


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
    con.commit()
    con.close()


def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()

    out_dir = "templates/partials"
    os.makedirs(out_dir, exist_ok=True)
    final_path = os.path.join(out_dir, "success_feedback.html")

    with feedback_lock:
        with open(final_path, "w", encoding="utf-8") as f:
            for row in data:
                f.write("<p>\n")
                f.write(html.escape(str(row[1])) + "\n")
                f.write("</p>\n")
    f.close()
