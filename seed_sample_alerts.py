import sqlite3
from datetime import datetime 

connection = sqlite3.connect("alerts.db")
cursor = connection.cursor()

cursor.execute('DROP TABLE IF EXISTS alerts')
cursor.execute(''' 
CREATE TABLE IF NOT EXISTS alerts (
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                port INTEGER,
                alert_type TEXT
)
''')

sample_alerts = [ 
    (str(datetime.now()), "192.168.1.10", "10.0.0.5", 22, "Multiple Packets"),
    (str(datetime.now()), "192.168.1.20", "10.0.0.5", 80, "Port Scan"),
    (str(datetime.now()), "192.168.1.30", "10.0.0.8", 443, "Multiple Packets")
]

for elements in sample_alerts: 
    cursor.execute(''' 
    INSERT INTO alerts (timestamp, src_ip, dst_ip, port, alert_type)
    VALUES (?,?,?,?,?)
    ''', elements)

# Save what I did
connection.commit()
connection.close()

print("SAMPLE ALERTS HAVE BEEN ADDED TO THE alerts.db")