import os
import sqlite3

# Path to the database file
db_path = os.path.join(os.getcwd(), 'database.db')
print("Database path:", db_path)

# Connect to the database
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Try to fetch tables
cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cur.fetchall()

print("Tables in the database:")
for table in tables:
    print(table[0])

conn.close()
