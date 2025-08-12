import sqlite3

# Connect SQL db 
connect = sqlite3.connect("alerts.db")
cursor = connect.cursor()

# Create table for the alert data 
cursor.execute('''
CREATE TABLE IF NOT EXISTS alerts(
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT, 
    port INTEGER, 
    alert_type TEXT
               )'''

)

connect.commit()
connect.close()