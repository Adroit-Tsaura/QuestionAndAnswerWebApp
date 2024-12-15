from flask import g 
import sqlite3 


def connect_db():
    conn = sqlite3.connect("question_answer.db")
    conn.row_factory = sqlite3.Row 
    return conn 

def get_db():
    if not hasattr(g, "sqlite3_db"):
        g.sqlite3_db = connect_db()
    return g.sqlite3_db 