from flask import Flask, render_template 
import sqlite3

app = Flask(__name__)

@app.route('/')
def dashboard():
    # connect db file to alerts
    conn = sqlite3.connect(
    "alerts.db")
    cursor = conn.cursor()
    cursor.execute('SELECT timestamp, src_ip AS source_ip, dst_ip AS destination_ip, port, alert_type FROM alerts')
    rows = cursor.fetchall()

    #Convert tuples to dicts 
    alerts = []
    for row in rows: 
        alerts.append({
            'timestamp': row[0],
            'src_ip': row[1],
            'dst_ip': row[2],
            'port': row[3],
            'alert_type': row[4]
        })

    # Close the connection
    conn.close()

   

    return render_template('dashboard.html', alerts=alerts)

# Run app if its the main 
if __name__ == '__main__': 
    app.run(debug=True)