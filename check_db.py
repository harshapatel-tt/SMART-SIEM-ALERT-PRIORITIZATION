import sqlite3

conn = sqlite3.connect("database/siem.db")
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
print("Database Tables:", cursor.fetchall())

cursor.execute("SELECT COUNT(*) FROM alerts")
print("Total Alerts:", cursor.fetchone()[0])

conn.close()