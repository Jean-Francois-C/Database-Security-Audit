## Database security audit and penetration testing

Training course materials and research notes that I created to teach how to perform a technical security assessment / penetration test of :  
➤ Relational databases: MS SQL, Oracle, MySQL, Sybase and PostgreSQL.  
➤ NoSQL databases: MongoDB, Redis.

### Content
```
➤ [Audit & Pentest] Reminder/General information (definitions)
➤ [Pentest] Database Penetration Testing (black box, grey box) - List of attacks 
➤ [Pentest] How to perform a network ports scan to locate a database
➤ [Pentest] How to perform brute-force & password spray attacks to identify valid database credentials (logins & passwords)
➤ [Pentest] How to check if a database is prone to known and unpatched vulnerabilities (e.g. obsolete database version, missing security patches)
➤ [Pentest] How to log into a database using valid credentials  
➤ [Audit & Pentest] How to identify and exploit database and OS privileges escalation vulnerabilities (including configuration review)
➤ [Audit & Pentest] How to dump and crack database password hashes
```
### Useful tools (DB penetration testing)
```
➤ NMAP - Network port scanner and (NSE) scripts (https://nmap.org)
➤ Database command-line clients (i.e. sql*plus, sqlcmd, mysql, psql, mongo, redis-cli, isql)
➤ Database GUI clients (e.g. DBvis (https://dbvis.com), Toad (https://www.quest.com/toad/))
➤ ODAT - Oracle Database Attacking Tool (https://github.com/quentinhardy/odat) 
➤ PowerUPsql - PowerShell Toolkit for Attacking SQL Server (https://github.com/NetSPI/PowerUpSQL)
➤ NoSQLmap - Automated NoSQL database enumeration and web application exploitation tool (https://github.com/codingo/NoSQLMap)
➤ Nosql-Exploitation-Framework - A FrameWork For NoSQL Scanning and Exploitation Framework (https://github.com/torque59/Nosql-Exploitation-Framework)
➤ Metasploit penetration testing framework (https://www.metasploit.com) 
➤ 'John the Ripper' - Password cracker (https://www.openwall.com/john/)
➤ Various scripts (source:kali/Github/your owns)
```
### Audit scripts (DB configuration review)
Security audit scripts that collect the main database configuration settings such as the list of DB accounts and their roles/privileges, the password hashes, the database server version, the audit log settings, ...
```
➤ MSSQL-Audit-Script.bat
➤ Oracle-Audit-Script.sql
➤ PostgreSQL-Audit-Script.sh
➤ MySQL-Audit-Script.sh
```
