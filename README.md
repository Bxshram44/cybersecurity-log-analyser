🔐 Cybersecurity Log Analyser

Project Overview:
A Python-based cybersecurity application that analyses login activity, identifies potentially suspicious patterns and generates security alerts.

I developed this project to strengthen my Python programming, data analysis and cybersecurity skills while gaining practical experience with security monitoring concepts.

The application includes an interactive dashboard built using Streamlit.

Features:
* Login Activity Analysis: Calculates total, successful and failed login attempts.
* Failure Rate Calculation: Identifies the percentage of unsuccessful login attempts.
* IP Address Analysis: Groups login activity by IP address.
* Suspicious Activity Detection: Flags IP addresses with repeated failed login attempts.
* Security Alerts: Categorises suspicious patterns using HIGH and MEDIUM severity levels.
* Data Visualisation: Displays login activity through interactive charts.
* CSV Upload: Allows users to analyse compatible login log datasets.
* Report Generation: Produces a downloadable CSV security report.

Technologies Used:
* Python – Core programming and security analysis logic
* Pandas – Data processing and analysis
* Streamlit – Interactive web dashboard
* CSV – Login log data storage and report exports
* Git and GitHub – Version control and project hosting
* GitHub Codespaces – Cloud-based development environment

How It Works:
1. The application loads a sample login dataset or accepts an uploaded CSV file.
2. Python processes the login records.
3. The application calculates login statistics and analyses activity by IP address.
4. Repeated failed login attempts are identified.
5. Potentially suspicious activity is assigned a severity level.
6. The dashboard presents the findings through tables, charts and security alerts.
7. Users can download a security report.

Example Results:
Using the simulated sample dataset:

Metric	Result:
Total login attempts	20
Successful logins	6
Failed logins	14
Login failure rate	70%
IP addresses triggering alerts	3

Skills Demonstrated:
-Python programming
-Data analysis and manipulation
-Cybersecurity log analysis
-Pattern recognition
-Conditional logic and automation
-Data visualisation
-Problem-solving
-Git and version control
-Web application deployment

Future Improvements:
* Add configurable security alert thresholds.
* Introduce date and time filtering.
* Improve visualisations of login activity over time.
* Add additional detection rules for unusual login behaviour.

⚠️DISCLAIMER⚠️:
This project uses simulated login data for educational purposes. Security alerts indicate patterns that may require investigation and do not confirm that a cyberattack has occurred.
