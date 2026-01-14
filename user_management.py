import sqlite3 as sql
import time
import random
import bcrypt
from cryptography.fernet import Fernet
import os

fernet = Fernet(os.environ["FERNET_KEY"])


def encrypt(data: str) -> bytes:
    return fernet.encrypt(data.encode())


def decrypt(data: bytes) -> str:
    return fernet.decrypt(data).decode()


# def insertUser(username, password, DoB):
#     con = sql.connect("database_files/database.db")
#     cur = con.cursor()
#     cur.execute(
#         "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
#         (username, password, DoB),
#     )
#     con.commit()
#     con.close()


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


# def retrieveUsers(username, password):
#     con = sql.connect("database_files/database.db")
#     cur = con.cursor()
#     cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
#     if cur.fetchone() == None:
#         con.close()
#         return False
#     else:
#         cur.execute(f"SELECT * FROM users WHERE password = '{password}'")
#         # Plain text log of visitor count as requested by Unsecure PWA management
#         with open("visitor_log.txt", "r") as file:
#             number = int(file.read().strip())
#             number += 1
#         with open("visitor_log.txt", "w") as file:
#             file.write(str(number))
#         # Simulate response time of heavy app for testing purposes
#         time.sleep(random.randint(80, 90) / 1000)
#         if cur.fetchone() == None:
#             con.close()
#             return False
#         else:
#             con.close()
#             return True


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
        # Visitor counter (unchanged)
        with open("visitor_log.txt", "r") as file:
            number = int(file.read().strip())
            number += 1
        with open("visitor_log.txt", "w") as file:
            file.write(str(number))

        time.sleep(random.randint(80, 90) / 1000)
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
    f = open("templates/partials/success_feedback.html", "w")
    for row in data:
        f.write("<p>\n")
        f.write(f"{row[1]}\n")
        f.write("</p>\n")
    f.close()
