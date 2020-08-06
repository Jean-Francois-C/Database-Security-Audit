#!/bin/sh
#----------------------------------------------------------------------------------------------------------------------------------------
# MySQL database security assessment script
# To run this script you need to do the following 2 steps:
# Step 1: Log into the Linux server hosting the MySQL database and copy the .sh script
# Step 2: Run the "MySQL-Audit-Script.sh" and type in the MySQL root's password when requested
#---------------------------------------------------------------------------------------------------------------------------------------
   
mysql -u root -p -h localhost mysql -e "
SELECT @@version; -- Display the MySQL DB version
SELECT @@hostname; -- Display the MySQL host name
SELECT @@datadir; -- Display the location of database files
SELECT user();  -- Display the current DB user 
SHOW variables; -- Display various database information including log settings
SHOW status; -- Display various database settings including up-time information
SELECT * FROM mysql.user; -- Display the list of DB accounts with their privileges, password hashes, ... 
SHOW databases;	-- Display the List of databases
SELECT host, user FROM mysql.user WHERE Super_priv = 'Y'; -- List DBA Accounts	
SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE privilege_type = 'SUPER'; -- List DBA Accounts	
SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE privilege_type = 'FILE'; -- List accounts with FILE privilege
SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE privilege_type = 'PROCESS'; -- List accounts with PROCESS privilege
SHOW PROCEDURE STATUS; -- List stored procedures and their DEFINER" >> /tmp/MySQL-Audit-Output.txt
# gzip /tmp/MySQL-Audit-Output.txt
# tar -czvf /tmp/MySQL-Audit-Output.tar.gz /tmp/MySQL-Audit-Output.txt

#---------------------------------------------------------------------------------------------------------------------------------------
# If you want to backup/dump only the MYSQL.user table or all the databases you can use the command "mysqldump"...
#---------------------------------------------------------------------------------------------------------------------------------------
# mysqldump -u root -p -h localhost mysql user > MySQL_USER_table_dump.sql
# gzip MySQL_USER_table_dump.sql
# mysqldump --opt --user=root --password --all-databases > MySQL_all_databases_dump.sql
# gzip MySQL_all_databases_dump.sql
