#!/bin/sh
#----------------------------------------------------------------------------------------------------------------------------------------
# Audit script to dump the table "mysql.user" that contains the list of database users with their password hashes and roles/privileges...
# To run this script you need to do the following 2 steps:
# Step 1: Log into the Linux server hosting the MySQL database
# Step 2: Run the "MySQL-Audit-Script.sh" and type in the MySQL root's password when requested
#---------------------------------------------------------------------------------------------------------------------------------------

mysqldump -u root -p -h localhost mysql user > MySQL_USER_table_dump.sql
gzip MySQL_USER_table_dump.sql
# tar -czvf MySQL_USER_table_dump.tar.gz ./MySQL_USER_table_dump.sql

# If you want to copy/dump all databases
# mysqldump --opt --user=root --password --all-databases > MySQL_all_databases_dump.sql
# gzip MySQL_all_databases_dump.sql
