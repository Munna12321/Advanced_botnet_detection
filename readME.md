Real-Time Advanced Botnet IP Analysis

This project is a real-time botnet monitoring and detection system developed using Python and Flask. It captures network traffic, detects potential botnet activities using IP reputation checks and behavioral analysis, and displays results on a web-based dashboard. Designed for educational and research purposes, it helps understand botnet detection through practical implementation.

💡 Key Features
Real-time IP monitoring: Tracks network traffic from connected clients.

AbuseIPDB integration: Checks IP reputation and flags malicious sources.

Behavioral analysis: Detects abnormal login attempts, high traffic volume, unusual ports, and process anomalies.

SQLite database storage: Logs alerts, client behavior, and predictions.

Interactive dashboard: Displays alerts and malicious activity with visual graphs.

Geolocation lookup: Shows the origin country, city, and ISP for flagged IPs.

📦 Technologies Used
Python (Flask, Requests, SQLite3)

HTML/CSS + JavaScript (for frontend dashboard)

AbuseIPDB API

Chart.js (for data visualization)

🚀 Future Enhancements
Add machine learning models for advanced behavioral analysis

Enhance client-side logging and detection

Email/notification alerts for admins

Dockerize for easier deployment