#!/bin/bash
######################################################################################################
# PostgreSQL security assessment script
# To run this script you need to do the following 3 steps:
# Step 1: Log into the Linux server hosting the PostgreSQL database with an admin account
# Step 2: Run the command "su postgres"
# Step 3: Run the script (e.g. located in /tmp/ and chmod 765)
######################################################################################################
 
#Set the value of variable
database="template1"

#Execute commands
psql -d $database -c 'SELECT VERSION()' > /tmp/PostgreSQL-Audit-Output.txt
echo '*********************************************************************' >> /tmp/PostgreSQL-Audit-Output.txt
psql -d $database -c '\l' >> /tmp/PostgreSQL-Audit-Output.txt
echo '*********************************************************************' >> /tmp/PostgreSQL-Audit-Output.txt
psql -d $database -c '\du' >> /tmp/PostgreSQL-Audit-Output.txt
echo '*********************************************************************' >> /tmp/PostgreSQL-Audit-Output.txt
psql -d $database -c '\dv' >> /tmp/PostgreSQL-Audit-Output.txt
echo '*********************************************************************' >> /tmp/PostgreSQL-Audit-Output.txt
psql -d $database -c '\dn+' >> /tmp/PostgreSQL-Audit-Output.txt
echo '*********************************************************************' >> /tmp/PostgreSQL-Audit-Output.txt
psql -d $database -c '\dp*' >> /tmp/PostgreSQL-Audit-Output.txt
echo '*********************************************************************' >> /tmp/PostgreSQL-Audit-Output.txt
echo 'Table pg_shadow' >> /tmp/PostgreSQL-Audit-Output.txt
psql -d $database -c 'SELECT * FROM pg_shadow' >> /tmp/PostgreSQL-Audit-Output.txt
echo '*********************************************************************' >> /tmp/PostgreSQL-Audit-Output.txt
echo 'Table pg_authid' >> /tmp/PostgreSQL-Audit-Output.txt
psql -d $database -c 'SELECT * FROM pg_authid' >> /tmp/PostgreSQL-Audit-Output.txt
echo '*********************************************************************' >> /tmp/PostgreSQL-Audit-Output.txt
psql -d $database -c 'show logging_collector' >> /tmp/PostgreSQL-Audit-Output.txt
echo '*********************************************************************' >> /tmp/PostgreSQL-Audit-Output.txt
psql -d $database -c 'show log_directory' >> /tmp/PostgreSQL-Audit-Output.txt
echo '*********************************************************************' >> /tmp/PostgreSQL-Audit-Output.txt
psql -d $database -c '\dy' >> /tmp/PostgreSQL-Audit-Output.txt
echo '*********************************************************************' >> /tmp/PostgreSQL-Audit-Output.txt
echo 'Table pg_settings' >> /tmp/PostgreSQL-Audit-Output.txt
psql -d $database -c 'SELECT * FROM pg_settings' >> /tmp/PostgreSQL-Audit-Output.txt
