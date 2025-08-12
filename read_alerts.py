import sqlite3

connection = sqlite3.connect("alerts.db")
cursor = connection.cursor()

# alerts the table name so asking cursor to get all 
# alert records 
cursor.execute("SELECT * FROM alerts")

# Fetch all all results (tuples)
rows = cursor.fetchall()

# Loop through the results and print them
print("\n=== STORED ALERTS ===\n")
for elements in rows: 
    timestamp, src_ip, dst_ip, port, alert_type = elements
    print(f"[{timestamp}] {alert_type} from {src_ip} to {dst_ip} on port {port}")

# Closing database connection, no corruption
connection.close()