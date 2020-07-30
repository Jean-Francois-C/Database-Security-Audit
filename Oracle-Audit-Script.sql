/* Basic Oracle database security assessment script                      */
/* To run this SQL script you need to do the following 2 steps:          */
/* Step 1: Log into the Oracle database using SQL*plus and a DBA account */
/* Step 2: Run the command @/Oracle-Audit-Script.sql                     */

set heading on
set echo on
set pause off
set termout off
set linesize 1000
set pagesize 50
set trim on
set wrap off
set colsep ""

/*
 * id.out file
 * V$VERSION displays information about the database version.
 * V$DATABASE displays information about the database from the control file.
 * V$PWFILE_USERS lists users who have been granted SYSDBA and SYSOPER privileges as derived from the password file.
*/
spool id.out
select * from v$version;
select * from v$database;
select * from v$pwfile_users;
spool off

/*
 * patches1.out & patches2.out file
 * It provides the list of patch installed.
 */
spool patches1.out
SELECT * FROM PRODUCT_COMPONENT_VERSION;
SELECT * FROM V$VERSION;
SELECT * FROM ALL_REGISTRY_BANNERS;
spool off

spool patches2.out
SELECT action_time, action, namespace, version, comments FROM dba_registry_history;
spool off

/*
 * For ORACLE >= 11g
 * dba_users1.out file
 * It provides information such as password, account status and default tablespace about all users of the database.
 */
spool dba_users1.out
select * from sys.user$ order by username;
spool off

/*
 * For ORACLE =< 10g
 * dba_users2.out file
 * It provides information such as password, account status and default tablespace about all users of the database.
 */
spool dba_users2.out
select * from sys.dba_users order by username;
spool off

/*
 * dba_profiles.out file
 * It displays all profiles (including password policies).
 */
spool dba_profiles.out
select * from sys.dba_profiles;
spool off

/*
 * dba_priv_audit_opts.out file
 * It describes current system privileges being audited across the system and by user.
 */
spool dba_priv_audit_opts.out
select * from sys.dba_priv_audit_opts;
spool off

/*
 * dba_stmt_audit_opts.out file
 * It describes current system auditing options.
 */
spool dba_stmt_audit_opts.out
select * from sys.dba_stmt_audit_opts;
spool off

/*
 * dba_obj_audit_opts.out file
 * It describes auditing options on all objects.
 */
spool dba_obj_audit_opts.out
select * from sys.dba_obj_audit_opts;
spool off

/*
 * links.out file
 */
spool links.out
select * from sys.link$;
spool off

spool all_db_links.out
select * from all_db_links;
spool off

/*
 * dba_db_links.out file
 * It describes all database links in the database. Its columns (except for PASSWORD) are the same as those in ALL_DB_LINKS.
 */
spool dba_db_links.out
select * from dba_db_links;
spool off

/*
 * dba_db_links_password.out file
 * It contains the output of the sys.link$ table. This table stored credential information in clear text used for the dblinks.
 */
spool dba_db_links_password.out
col link for a30
col username for a10
col host     for a20
col owner    for a10
select l.name link, l.userid username, l.host, l.ctime created, u.name owner,
l.password from   sys.link$ l, sys.user$ u
where  l.OWNER# = u.USER#; 
spool off

/*
 * views_privileged.out file
 * It displays the views that have access granted other than select access.
 */
spool views_privileged.out
col grantee for a20
col privilege for a10
col table_name for a30
select grantee,table_name,privilege
from dba_tab_privs
where exists (select 'x' from dba_views where view_name=table_name)
and privilege<>'SELECT'
union
select grantee,table_name,privilege
from dba_col_privs
where exists (select 'x' from dba_views where view_name=table_name)
and privilege <>'SELECT';
spool off

/*
 * dba_table.out file
 * It lists all tables of the database (all users).
 */
spool dba_table.out
select owner, tablespace_name, table_name from dba_tables;
spool off

/*
 * dba_tablespaces.out file
 * It describes all tablespaces in the database.
 */
spool dba_tablespaces.out
select * from dba_tablespaces;
spool off

/*
 * dba_roles.out file
 * It lists all roles that exist in the database.
 */
spool dba_roles.out
select * from dba_roles;
spool off

/*
 * dba_role_privs.out file
 * It describes the roles granted to all users and roles in the database.
 */
spool dba_role_privs.out
select * from dba_role_privs;
spool off

/*
 * role_role_privs.out file
 * It describes the roles granted to roles in the database.
 */
spool role_role_privs.out
select * from role_role_privs;
spool off

/*
 * dba_tab_privs.out file
 * It describes all object grants in the database.
 */
spool dba_tab_privs.out
select * from dba_tab_privs;
spool off

/*
 * dba_sys_privs.out file
 * It describes system privileges granted to users and roles.
 */
spool dba_sys_privs.out
select * from dba_sys_privs;
spool off

/*
 * role_tab_privs.out file
 * It describes table privileges granted to roles.
 */
spool role_tab_privs.out
select * from role_tab_privs;
spool off

/*
 * dba_col_privs.out file
 * It describes all column object grants in the database.
 */
spool dba_col_privs.out
select * from dba_col_privs;
spool off

/*
 * audit.out file
 * It use information from V$PARAMETER to retrieve audit settings.
 */
spool audit.out
select name,value from v$parameter where name like 'audit%';
spool off

/*
 * vparameter.out file
 * It displays information about the initialization parameters that are currently in effect for the session.
 */
spool vparameter.out
select * from v$parameter;
spool off

/*
 * parameters.out file
 * It displays the current values for one or more initialization parameters.
 */
spool parameters.out
show parameters;
spool off

/*
 * schema.out file
 * Displays the data schema.
 */
spool schema.out
set pages 50000
set null 'No Comments'

tti 'Table Comments'
col comments format a29 wrap word

select * from all_tab_comments where owner not in
    ('SYS','SYSTEM');

tti 'Column Comments'
col comments format a18 wrap word
break on table_name skip 1
select * from all_col_comments
where owner not in
    ('SYS','SYSTEM');
clear break

set null ''
set pages 23
spool off

quit
