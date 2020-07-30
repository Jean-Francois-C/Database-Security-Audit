#!/bin/sh
#----------------------------------------------------------------------------------------------------------------------------------------
# Basic script to dump the table "mysql.user" that contains the list of database users, password hashes, privileges...
# To run this script you need to do the following 2 steps:
# Log into the Linux server hosting the MySQL database
# Run the "MySQL-Audit-Script.sh" and type in the MySQL root's password when requested
#---------------------------------------------------------------------------------------------------------------------------------------

mysqldump -u root -p -h localhost mysql user > MySQL_USER_table_dump.sql
gzip MySQL_USER_table_dump.sql

# mysqldump --opt --user=root --password --all-databases > MySQL_all_databases_dump.sql
# gzip MySQL_all_databases_dump.sql
