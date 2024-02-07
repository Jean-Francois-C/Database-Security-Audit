## Database security audit and penetration testing

Training course materials and research notes that I created to teach how to perform a technical security assessment / penetration test of :  
| Category | Database |
| :-----: | :-----: | 
| Relational database | [MS SQL server](https://github.com/Jean-Francois-C/Database-Security-Audit/blob/master/MSSQL%20database%20penetration%20testing) | 
| Relational database | [Oracle](https://github.com/Jean-Francois-C/Database-Security-Audit/blob/master/ORACLE%20database%20penetration%20testing) | 
| Relational database | [PostgreSQL](https://github.com/Jean-Francois-C/Database-Security-Audit/blob/master/PostgreSQL%20database%20penetration%20testing)|
| Relational database | [MySQL](https://github.com/Jean-Francois-C/Database-Security-Audit/blob/master/MySQL%20database%20penetration%20testing) |
| Relational database | [Sybase](https://github.com/Jean-Francois-C/Database-Security-Audit/blob/master/SYBASE%20database%20penetration%20testing) |
| NoSQL database | [MongoDB](https://github.com/Jean-Francois-C/Database-Security-Audit/blob/master/MongoDB%20penetration%20testing) |
| NoSQL database| [Redis](https://github.com/Jean-Francois-C/Database-Security-Audit/blob/master/Redis%20database%20penetration%20testing) |  

### Table of Contents
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
### Useful resources (DB security)
```
➤ CIS Benchmark - Secure configuration guidelines 
  - MongoDB database 
    ➤ https://www.cisecurity.org/benchmark/mongodb
  - MySQL database 
    ➤ https://www.cisecurity.org/benchmark/oracle_mysql
  - Oracle database 
    ➤ https://www.cisecurity.org/benchmark/oracle_database
  - PostgreSQL database 
    ➤ https://www.cisecurity.org/benchmark/postgresql
  - MSSQL Server database
    ➤ https://www.cisecurity.org/benchmark/microsoft_sql_server

➤ Microsoft SQL server database security guides
  - SQL Server security best practices
    ➤ https://learn.microsoft.com/en-us/sql/relational-databases/security/sql-server-security-best-practices?view=sql-server-ver16
  - Securing SQL Server
    ➤ https://learn.microsoft.com/en-us/sql/relational-databases/security/securing-sql-server?view=sql-server-ver16

➤ Oracle® database security guides
  - https://docs.oracle.com/en//database/oracle/oracle-database/23/dbseg/database-security-guide.pdf
  - https://www.oracle.com/security/database-security/

➤ MySQL Secure Deployment Guide
  - https://downloads.mysql.com/docs/mysql-secure-deployment-guide-8.0-en.pdf
  - https://dev.mysql.com/doc/refman/8.3/en/security-guidelines.html
```
