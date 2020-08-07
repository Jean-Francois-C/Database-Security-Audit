@echo off
REM -------------------------------------------------------------------------------------------------------------------------------------------
REM MSSQL security assessment script
REM To run this script you need to do the following 3 steps:
REM Step 1: Log into the Windows server hosting the MS SQL database
REM Step 2: Start a PowerShell console with a Windows account that has DBA privileges (e.g. runas /noprofile /user:Domain\account powershell) 
REM Step 3: Run this ".bat" script
REM -------------------------------------------------------------------------------------------------------------------------------------------

set /p server= Please type in the server name and instance name (such as : server-name\instance-name or just the server-name for the default instance):
echo.
set /p analysis= Please type in a name for the current analysis, do not include spaces:
echo.
echo Creating Output directory
mkdir Output-%analysis%
mkdir Output-%analysis%\commands
mkdir Output-%analysis%\results
set DIR_RESULTS=Output-%analysis%\results
set DIR_CMDS=Output-%analysis%\commands
net accounts > %DIR_RESULTS%\windows-local-account-policy.txt
net start > %DIR_RESULTS%\windows-services.txt
net user > %DIR_RESULTS%\windows-local-users.txt
net localgroup > %DIR_RESULTS%\windows-local-groups.txt
net localgroup Administrators > %DIR_RESULTS%\windows-local-admin-group.txt
systeminfo > %DIR_RESULTS%\windows-systeminfo.txt

@echo on
echo set nocount on > %DIR_CMDS%\dbnm.sql
echo select @@servername, @@version, getdate() >> %DIR_CMDS%\dbnm.sql
echo go >> %DIR_CMDS%\dbnm.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\dbnm.sql -o%DIR_RESULTS%\dbnm.txt

echo set nocount on > %DIR_CMDS%\audit.sql
echo exec xp_loginconfig >> %DIR_CMDS%\audit.sql
echo go >> %DIR_CMDS%\audit.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\audit.sql -o%DIR_RESULTS%\audit.txt

echo set nocount on > %DIR_CMDS%\sphelpdb.sql
echo exec sp_helpdb>> %DIR_CMDS%\sphelpdb.sql
echo go >> %DIR_CMDS%\sphelpdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sphelpdb.sql -o%DIR_RESULTS%\sphelpdb.txt

echo set nocount on > %DIR_CMDS%\dormantpassword_master.sql
echo use master >> %DIR_CMDS%\dormantpassword_master.sql
echo go >> %DIR_CMDS%\dormantpassword_master.sql
echo select sid, name, type_desc, is_disabled, modify_date from sys.server_principals where datediff(day, modify_date, getdate()) ^> 60 order by modify_date >> %DIR_CMDS%\dormantpassword_master.sql
echo go >> %DIR_CMDS%\dormantpassword_master.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\dormantpassword_master.sql -o%DIR_RESULTS%\dormantpassword_master.txt

echo set nocount on > %DIR_CMDS%\MSreplication_options.sql
echo use master >> %DIR_CMDS%\MSreplication_options.sql
echo go >> %DIR_CMDS%\MSreplication_options.sql
echo SELECT * from MSreplication_options >> %DIR_CMDS%\MSreplication_options.sql
echo go >> %DIR_CMDS%\MSreplication_options.sql
sqlcmd -S%server% -E -s";" -w500 -dmaster -i%DIR_CMDS%\MSreplication_options.sql -o%DIR_RESULTS%\MSreplication_options.txt

echo set nocount on > %DIR_CMDS%\sysalerts.sql
echo use msdb >> %DIR_CMDS%\sysalerts.sql
echo go >> %DIR_CMDS%\sysalerts.sql
echo SELECT * from sysalerts >> %DIR_CMDS%\sysalerts.sql
echo go >> %DIR_CMDS%\sysalerts.sql
sqlcmd -S%server% -E -s";" -w500 -dmsdb -i%DIR_CMDS%\sysalerts.sql -o%DIR_RESULTS%\sysalerts.txt

echo set nocount on > %DIR_CMDS%\sysassemblies.sql
echo use master >> %DIR_CMDS%\sysassemblies.sql
echo go >> %DIR_CMDS%\sysassemblies.sql
echo SELECT name, permission_set_desc from sys.assemblies where is_user_defined = 1 >> %DIR_CMDS%\sysassemblies.sql
echo go >> %DIR_CMDS%\sysassemblies.sql
sqlcmd -S%server% -E -s";" -w500 -dmaster -i%DIR_CMDS%\sysassemblies.sql -o%DIR_RESULTS%\sysassemblies.txt

echo set nocount on > %DIR_CMDS%\sysaltfiles.sql
echo use master >> %DIR_CMDS%\sysaltfiles.sql
echo go >> %DIR_CMDS%\sysaltfiles.sql
echo SELECT * from sys.master_files >> %DIR_CMDS%\sysaltfiles.sql
echo go >> %DIR_CMDS%\sysaltfiles.sql
sqlcmd -S%server% -E -s";" -w500 -dmaster -i%DIR_CMDS%\sysaltfiles.sql -o%DIR_RESULTS%\sysaltfiles.txt

echo set nocount on > %DIR_CMDS%\syscategories.sql
echo use msdb >> %DIR_CMDS%\syscategories.sql
echo go >> %DIR_CMDS%\syscategories.sql
echo SELECT * from syscategories >> %DIR_CMDS%\syscategories.sql
echo go >> %DIR_CMDS%\syscategories.sql
sqlcmd -S%server% -E -s";" -w500 -dmsdb -i%DIR_CMDS%\syscategories.sql -o%DIR_RESULTS%\syscategories.txt

echo set nocount on > %DIR_CMDS%\sysconfigures.sql
echo use master >> %DIR_CMDS%\sysconfigures.sql
echo go >> %DIR_CMDS%\sysconfigures.sql
echo SELECT * from sys.configurations >> %DIR_CMDS%\sysconfigures.sql
echo go >> %DIR_CMDS%\sysconfigures.sql
sqlcmd -S%server% -E -s";" -w500 -dmaster -i%DIR_CMDS%\sysconfigures.sql -o%DIR_RESULTS%\sysconfigures.txt

echo set nocount on > %DIR_CMDS%\sysdatabases.sql
echo use master >> %DIR_CMDS%\sysdatabases.sql
echo go >> %DIR_CMDS%\sysdatabases.sql
echo SELECT * from sys.databases >> %DIR_CMDS%\sysdatabases.sql
echo go >> %DIR_CMDS%\sysdatabases.sql
sqlcmd -S%server% -E -s";" -w500 -dmaster -i%DIR_CMDS%\sysdatabases.sql -o%DIR_RESULTS%\sysdatabases.txt

echo set nocount on > %DIR_CMDS%\sysdevices.sql
echo use master >> %DIR_CMDS%\sysdevices.sql
echo go >> %DIR_CMDS%\sysdevices.sql
echo SELECT * from sys.backup_devices >> %DIR_CMDS%\sysdevices.sql
echo go >> %DIR_CMDS%\sysdevices.sql
sqlcmd -S%server% -E -s";" -w500 -dmaster -i%DIR_CMDS%\sysdevices.sql -o%DIR_RESULTS%\sysdevices.txt

echo set nocount on > %DIR_CMDS%\sysjobhistory.sql
echo use msdb >> %DIR_CMDS%\sysjobhistory.sql
echo go >> %DIR_CMDS%\sysjobhistory.sql
echo SELECT * from sysjobhistory >> %DIR_CMDS%\sysjobhistory.sql
echo go >> %DIR_CMDS%\sysjobhistory.sql
sqlcmd -S%server% -E -s";" -w500 -dmsdb -i%DIR_CMDS%\sysjobhistory.sql -o%DIR_RESULTS%\sysjobhistory.txt

echo set nocount on > %DIR_CMDS%\sysjobs.sql
echo use msdb >> %DIR_CMDS%\sysjobs.sql
echo go >> %DIR_CMDS%\sysjobs.sql
echo SELECT * from sysjobs >> %DIR_CMDS%\sysjobs.sql
echo go >> %DIR_CMDS%\sysjobs.sql
sqlcmd -S%server% -E -s";" -w500 -dmsdb -i%DIR_CMDS%\sysjobs.sql -o%DIR_RESULTS%\sysjobs.txt

echo set nocount on > %DIR_CMDS%\sysjobschedules.sql
echo use msdb >> %DIR_CMDS%\sysjobschedules.sql
echo go >> %DIR_CMDS%\sysjobschedules.sql
echo SELECT * from sysjobschedules >> %DIR_CMDS%\sysjobschedules.sql
echo go >> %DIR_CMDS%\sysjobschedules.sql
sqlcmd -S%server% -E -s";" -w500 -dmsdb -i%DIR_CMDS%\sysjobschedules.sql -o%DIR_RESULTS%\sysjobschedules.txt

echo set nocount on > %DIR_CMDS%\sysjobservers.sql
echo use msdb >> %DIR_CMDS%\sysjobservers.sql
echo go >> %DIR_CMDS%\sysjobservers.sql
echo SELECT * from sysjobservers >> %DIR_CMDS%\sysjobservers.sql
echo go >> %DIR_CMDS%\sysjobservers.sql
sqlcmd -S%server% -E -s";" -w500 -dmsdb -i%DIR_CMDS%\sysjobservers.sql -o%DIR_RESULTS%\sysjobservers.txt

echo set nocount on > %DIR_CMDS%\sysjobsteps.sql
echo use msdb >> %DIR_CMDS%\sysjobsteps.sql
echo go >> %DIR_CMDS%\sysjobsteps.sql
echo SELECT * from sysjobsteps >> %DIR_CMDS%\sysjobsteps.sql
echo go >> %DIR_CMDS%\sysjobsteps.sql
sqlcmd -S%server% -E -s";" -w500 -dmsdb -i%DIR_CMDS%\sysjobsteps.sql -o%DIR_RESULTS%\sysjobsteps.txt

echo set nocount on > %DIR_CMDS%\sysoledbusers.sql
echo use msdb >> %DIR_CMDS%\sysoledbusers.sql
echo go >> %DIR_CMDS%\sysoledbusers.sql
echo SELECT * from sysoledbusers >> %DIR_CMDS%\sysoledbusers.sql
echo go >> %DIR_CMDS%\sysoledbusers.sql
sqlcmd -S%server% -E -s";" -w500 -dmsdb -i%DIR_CMDS%\sysoledbusers.sql -o%DIR_RESULTS%\sysoledbusers.txt

echo set nocount on > %DIR_CMDS%\syssvrroles.sql
echo use master >> %DIR_CMDS%\syssvrroles.sql
echo go >> %DIR_CMDS%\syssvrroles.sql
echo SELECT pr.name, pr.is_disabled, pr.is_fixed_role, pr.create_date, pr.modify_date, pr.default_database_name, owner.name AS owner_name FROM sys.server_principals AS pr JOIN sys.server_principals AS owner ON pr.owning_principal_id = owner.principal_id WHERE pr.type = 'R' ORDER BY name >> %DIR_CMDS%\syssvrroles.sql
echo go >> %DIR_CMDS%\syssvrroles.sql
sqlcmd -S%server% -E    -s";" -w500 -dmaster -i%DIR_CMDS%\syssvrroles.sql -o%DIR_RESULTS%\syssvrroles.txt

echo set nocount on > %DIR_CMDS%\syssvrrolemembers.sql
echo use master >> %DIR_CMDS%\syssvrrolemembers.sql
echo go >> %DIR_CMDS%\syssvrrolemembers.sql
echo SELECT role.name AS role_name, member.name AS member_name from sys.server_role_members JOIN sys.server_principals AS role ON sys.server_role_members.role_principal_id = role.principal_id JOIN sys.server_principals AS member ON sys.server_role_members.member_principal_id = member.principal_id >> %DIR_CMDS%\syssvrrolemembers.sql
echo go >> %DIR_CMDS%\syssvrrolemembers.sql
sqlcmd -S%server% -E -s";" -w500 -dmaster -i%DIR_CMDS%\syssvrrolemembers.sql -o%DIR_RESULTS%\syssvrrolemembers.txt

echo set nocount on > %DIR_CMDS%\sysserverpermissions.sql
echo use master >> %DIR_CMDS%\syserverpermissions.sql
echo go >> %DIR_CMDS%\syserverpermissions.sql
echo SELECT pr.name, pe.state_desc, pe.permission_name FROM sys.server_principals AS pr JOIN sys.server_permissions AS pe ON pe.grantee_principal_id = pr.principal_id WHERE pr.type = 'R' ORDER BY name >> %DIR_CMDS%\sysserverpermissions.sql
echo go >> %DIR_CMDS%\sysserverpermissions.sql
sqlcmd -S%server% -E -s";" -w500 -dmaster -i%DIR_CMDS%\sysserverpermissions.sql -o%DIR_RESULTS%\sysserverpermissions.txt

echo set nocount on > %DIR_CMDS%\syslogins.sql
echo use master >> %DIR_CMDS%\syslogins.sql
echo go >> %DIR_CMDS%\syslogins.sql
echo SELECT createdate, updatedate, name, dbname, password, denylogin, hasaccess, isntname, isntgroup, isntuser, sysadmin, securityadmin, bulkadmin, serveradmin, setupadmin, processadmin, diskadmin, dbcreator, loginname  from syslogins >> %DIR_CMDS%\syslogins.sql
echo go >> %DIR_CMDS%\syslogins.sql
sqlcmd -S%server% -E -s";" -w500 -dmaster -i%DIR_CMDS%\syslogins.sql -o%DIR_RESULTS%\syslogins.txt

echo set nocount on > %DIR_CMDS%\syssqllogins.sql
echo use master >> %DIR_CMDS%\syssqllogins.sql
echo go >> %DIR_CMDS%\syssqllogins.sql
echo SELECT * from sys.sql_logins >> %DIR_CMDS%\syssqllogins.sql
echo go >> %DIR_CMDS%\syssqllogins.sql
sqlcmd -S%server% -E -s";" -w500 -dmaster -i%DIR_CMDS%\syssqllogins.sql -o%DIR_RESULTS%\password_hashs.txt

echo set nocount on > %DIR_CMDS%\sysnotifications.sql
echo use msdb >> %DIR_CMDS%\sysnotifications.sql
echo go >> %DIR_CMDS%\sysnotifications.sql
echo SELECT * from sysnotifications >> %DIR_CMDS%\sysnotifications.sql
echo go >> %DIR_CMDS%\sysnotifications.sql
sqlcmd -S%server% -E -s";" -w500 -dmsdb -i%DIR_CMDS%\sysnotifications.sql -o%DIR_RESULTS%\sysnotifications.txt

echo set nocount on > %DIR_CMDS%\sysoperators.sql
echo use msdb >> %DIR_CMDS%\sysoperators.sql
echo go >> %DIR_CMDS%\sysoperators.sql
echo SELECT * from sysoperators >> %DIR_CMDS%\sysoperators.sql
echo go >> %DIR_CMDS%\sysoperators.sql
sqlcmd -S%server% -E -s";" -w500 -dmsdb -i%DIR_CMDS%\sysoperators.sql -o%DIR_RESULTS%\sysoperators.txt

echo set nocount on > %DIR_CMDS%\sysprocesses.sql
echo use master >> %DIR_CMDS%\sysprocesses.sql
echo go >> %DIR_CMDS%\sysprocesses.sql
echo SELECT * from sysprocesses >> %DIR_CMDS%\sysprocesses.sql
echo go >> %DIR_CMDS%\sysprocesses.sql
sqlcmd -S%server% -E -s";" -w500 -dmaster -i%DIR_CMDS%\sysprocesses.sql -o%DIR_RESULTS%\sysprocesses.txt

echo set nocount on > %DIR_CMDS%\sysremotelogins.sql
echo use master >> %DIR_CMDS%\sysremotelogins.sql
echo go >> %DIR_CMDS%\sysremotelogins.sql
echo SELECT * from sys.remote_logins >> %DIR_CMDS%\sysremotelogins.sql
echo go >> %DIR_CMDS%\sysremotelogins.sql
sqlcmd -S%server% -E -s";" -w500 -dmaster -i%DIR_CMDS%\sysremotelogins.sql -o%DIR_RESULTS%\sysremotelogins.txt

echo set nocount on > %DIR_CMDS%\sysservers.sql
echo use master >> %DIR_CMDS%\sysservers.sql
echo go >> %DIR_CMDS%\sysservers.sql
echo SELECT * from sys.servers >> %DIR_CMDS%\sysservers.sql
echo go >> %DIR_CMDS%\sysservers.sql
sqlcmd -S%server% -E -s";" -w500 -dmaster -i%DIR_CMDS%\sysservers.sql -o%DIR_RESULTS%\sysservers.txt

echo set nocount on > %DIR_CMDS%\sp_helpuser_master.sql
echo use master >> %DIR_CMDS%\sp_helpuser_master.sql
echo exec sp_helpuser >> %DIR_CMDS%\sp_helpuser_master.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpuser_master.sql -o%DIR_RESULTS%\sp_helpuser_master.txt

echo set nocount on > %DIR_CMDS%\sp_helprotect_master.sql
echo use master >> %DIR_CMDS%\sp_helprotect_master.sql
echo exec sp_helprotect >> %DIR_CMDS%\sp_helprotect_master.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprotect_master.sql -o%DIR_RESULTS%\sp_helprotect_master.txt

echo set nocount on > %DIR_CMDS%\sp_helprolemember_master.sql
echo use master >> %DIR_CMDS%\sp_helprolemember_master.sql
echo exec sp_helprolemember >> %DIR_CMDS%\sp_helprolemember_master.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprolemember_master.sql -o%DIR_RESULTS%\sp_helprolemember_master.txt

echo set nocount on > %DIR_CMDS%\sp_helpciphersym_master.sql
echo use master >> %DIR_CMDS%\sp_helpciphersym_master.sql
echo go >> %DIR_CMDS%\sp_helpciphersym_master.sql
echo SELECT * from sys.symmetric_ksql WHERE db_id()^>4 >> %DIR_CMDS%\sp_helpciphersym_master.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprolemember_master.sql -o%DIR_RESULTS%\sp_helprolemember_master.txt

echo go >> %DIR_CMDS%\sp_helpciphersym_master.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpciphersym_master.sql -o%DIR_RESULTS%\sp_helpciphersym_master.txt

echo set nocount on > %DIR_CMDS%\sp_helpcipherasym_master.sql
echo use master >> %DIR_CMDS%\sp_helpcipherasym_master.sql
echo go >> %DIR_CMDS%\sp_helpcipherasym_master.sql
echo SELECT * from sys.asymmetric_ksql WHERE db_id()^>4 >> %DIR_CMDS%\sp_helpcipherasym_master.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpciphersym_master.sql -o%DIR_RESULTS%\sp_helpciphersym_master.txt

echo go >> %DIR_CMDS%\sp_helpcipherasym_master.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpcipherasym_master.sql -o%DIR_RESULTS%\sp_helpcipherasym_master.txt

echo set nocount on > %DIR_CMDS%\sp_helpuser_tempdb.sql
echo use tempdb >> %DIR_CMDS%\sp_helpuser_tempdb.sql
echo exec sp_helpuser >> %DIR_CMDS%\sp_helpuser_tempdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpuser_tempdb.sql -o%DIR_RESULTS%\sp_helpuser_tempdb.txt

echo set nocount on > %DIR_CMDS%\sp_helprotect_tempdb.sql
echo use tempdb >> %DIR_CMDS%\sp_helprotect_tempdb.sql
echo exec sp_helprotect >> %DIR_CMDS%\sp_helprotect_tempdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprotect_tempdb.sql -o%DIR_RESULTS%\sp_helprotect_tempdb.txt


echo set nocount on > %DIR_CMDS%\sp_helprolemember_tempdb.sql
echo use tempdb >> %DIR_CMDS%\sp_helprolemember_tempdb.sql
echo exec sp_helprolemember >> %DIR_CMDS%\sp_helprolemember_tempdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprolemember_tempdb.sql -o%DIR_RESULTS%\sp_helprolemember_tempdb.txt

echo set nocount on > %DIR_CMDS%\sp_helpciphersym_tempdb.sql
echo use tempdb >> %DIR_CMDS%\sp_helpciphersym_tempdb.sql
echo go >> %DIR_CMDS%\sp_helpciphersym_tempdb.sql
echo SELECT * from sys.symmetric_ksql WHERE db_id()^>4 >> %DIR_CMDS%\sp_helpciphersym_tempdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprolemember_tempdb.sql -o%DIR_RESULTS%\sp_helprolemember_tempdb.txt

echo go >> %DIR_CMDS%\sp_helpciphersym_tempdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpciphersym_tempdb.sql -o%DIR_RESULTS%\sp_helpciphersym_tempdb.txt

echo set nocount on > %DIR_CMDS%\sp_helpcipherasym_tempdb.sql
echo use tempdb >> %DIR_CMDS%\sp_helpcipherasym_tempdb.sql
echo go >> %DIR_CMDS%\sp_helpcipherasym_tempdb.sql
echo SELECT * from sys.asymmetric_ksql WHERE db_id()^>4 >> %DIR_CMDS%\sp_helpcipherasym_tempdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpciphersym_tempdb.sql -o%DIR_RESULTS%\sp_helpciphersym_tempdb.txt

echo go >> %DIR_CMDS%\sp_helpcipherasym_tempdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpcipherasym_tempdb.sql -o%DIR_RESULTS%\sp_helpcipherasym_tempdb.txt

echo set nocount on > %DIR_CMDS%\sp_helpuser_model.sql
echo use model >> %DIR_CMDS%\sp_helpuser_model.sql
echo exec sp_helpuser >> %DIR_CMDS%\sp_helpuser_model.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpuser_model.sql -o%DIR_RESULTS%\sp_helpuser_model.txt

echo set nocount on > %DIR_CMDS%\sp_helprotect_model.sql
echo use model >> %DIR_CMDS%\sp_helprotect_model.sql
echo exec sp_helprotect >> %DIR_CMDS%\sp_helprotect_model.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprotect_model.sql -o%DIR_RESULTS%\sp_helprotect_model.txt

echo set nocount on > %DIR_CMDS%\sp_helprolemember_model.sql
echo use model >> %DIR_CMDS%\sp_helprolemember_model.sql
echo exec sp_helprolemember >> %DIR_CMDS%\sp_helprolemember_model.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprolemember_model.sql -o%DIR_RESULTS%\sp_helprolemember_model.txt

echo set nocount on > %DIR_CMDS%\sp_helpciphersym_model.sql
echo use model >> %DIR_CMDS%\sp_helpciphersym_model.sql
echo go >> %DIR_CMDS%\sp_helpciphersym_model.sql
echo SELECT * from sys.symmetric_ksql WHERE db_id()^>4 >> %DIR_CMDS%\sp_helpciphersym_model.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprolemember_model.sql -o%DIR_RESULTS%\sp_helprolemember_model.txt

echo go >> %DIR_CMDS%\sp_helpciphersym_model.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpciphersym_model.sql -o%DIR_RESULTS%\sp_helpciphersym_model.txt

echo set nocount on > %DIR_CMDS%\sp_helpcipherasym_model.sql
echo use model >> %DIR_CMDS%\sp_helpcipherasym_model.sql
echo go >> %DIR_CMDS%\sp_helpcipherasym_model.sql
echo SELECT * from sys.asymmetric_ksql WHERE db_id()^>4 >> %DIR_CMDS%\sp_helpcipherasym_model.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpciphersym_model.sql -o%DIR_RESULTS%\sp_helpciphersym_model.txt

echo go >> %DIR_CMDS%\sp_helpcipherasym_model.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpcipherasym_model.sql -o%DIR_RESULTS%\sp_helpcipherasym_model.txt

echo set nocount on > %DIR_CMDS%\sp_helpuser_msdb.sql
echo use msdb >> %DIR_CMDS%\sp_helpuser_msdb.sql
echo exec sp_helpuser >> %DIR_CMDS%\sp_helpuser_msdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpuser_msdb.sql -o%DIR_RESULTS%\sp_helpuser_msdb.txt

echo set nocount on > %DIR_CMDS%\sp_helprotect_msdb.sql
echo use msdb >> %DIR_CMDS%\sp_helprotect_msdb.sql
echo exec sp_helprotect >> %DIR_CMDS%\sp_helprotect_msdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprotect_msdb.sql -o%DIR_RESULTS%\sp_helprotect_msdb.txt

echo set nocount on > %DIR_CMDS%\sp_helprolemember_msdb.sql
echo use msdb >> %DIR_CMDS%\sp_helprolemember_msdb.sql
echo exec sp_helprolemember >> %DIR_CMDS%\sp_helprolemember_msdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprolemember_msdb.sql -o%DIR_RESULTS%\sp_helprolemember_msdb.txt

echo set nocount on > %DIR_CMDS%\sp_helpciphersym_msdb.sql
echo use msdb >> %DIR_CMDS%\sp_helpciphersym_msdb.sql
echo go >> %DIR_CMDS%\sp_helpciphersym_msdb.sql
echo SELECT * from sys.symmetric_ksql WHERE db_id()^>4 >> %DIR_CMDS%\sp_helpciphersym_msdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprolemember_msdb.sql -o%DIR_RESULTS%\sp_helprolemember_msdb.txt

echo go >> %DIR_CMDS%\sp_helpciphersym_msdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpciphersym_msdb.sql -o%DIR_RESULTS%\sp_helpciphersym_msdb.txt

echo set nocount on > %DIR_CMDS%\sp_helpcipherasym_msdb.sql
echo use msdb >> %DIR_CMDS%\sp_helpcipherasym_msdb.sql
echo go >> %DIR_CMDS%\sp_helpcipherasym_msdb.sql
echo SELECT * from sys.asymmetric_ksql WHERE db_id()^>4 >> %DIR_CMDS%\sp_helpcipherasym_msdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpciphersym_msdb.sql -o%DIR_RESULTS%\sp_helpciphersym_msdb.txt

echo go >> %DIR_CMDS%\sp_helpcipherasym_msdb.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpcipherasym_msdb.sql -o%DIR_RESULTS%\sp_helpcipherasym_msdb.txt

echo set nocount on > %DIR_CMDS%\sp_helpuser_ReportServer.sql
echo use ReportServer >> %DIR_CMDS%\sp_helpuser_ReportServer.sql
echo exec sp_helpuser >> %DIR_CMDS%\sp_helpuser_ReportServer.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpuser_ReportServer.sql -o%DIR_RESULTS%\sp_helpuser_ReportServer.txt

echo set nocount on > %DIR_CMDS%\sp_helprotect_ReportServer.sql
echo use ReportServer >> %DIR_CMDS%\sp_helprotect_ReportServer.sql
echo exec sp_helprotect >> %DIR_CMDS%\sp_helprotect_ReportServer.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprotect_ReportServer.sql -o%DIR_RESULTS%\sp_helprotect_ReportServer.txt

echo set nocount on > %DIR_CMDS%\sp_helprolemember_ReportServer.sql
echo use ReportServer >> %DIR_CMDS%\sp_helprolemember_ReportServer.sql
echo exec sp_helprolemember >> %DIR_CMDS%\sp_helprolemember_ReportServer.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprolemember_ReportServer.sql -o%DIR_RESULTS%\sp_helprolemember_ReportServer.txt

echo set nocount on > %DIR_CMDS%\sp_helpciphersym_ReportServer.sql
echo use ReportServer >> %DIR_CMDS%\sp_helpciphersym_ReportServer.sql
echo go >> %DIR_CMDS%\sp_helpciphersym_ReportServer.sql
echo SELECT * from sys.symmetric_ksql WHERE db_id()^>4 >> %DIR_CMDS%\sp_helpciphersym_ReportServer.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprolemember_ReportServer.sql -o%DIR_RESULTS%\sp_helprolemember_ReportServer.txt

echo go >> %DIR_CMDS%\sp_helpciphersym_ReportServer.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpciphersym_ReportServer.sql -o%DIR_RESULTS%\sp_helpciphersym_ReportServer.txt

echo set nocount on > %DIR_CMDS%\sp_helpcipherasym_ReportServer.sql
echo use ReportServer >> %DIR_CMDS%\sp_helpcipherasym_ReportServer.sql
echo go >> %DIR_CMDS%\sp_helpcipherasym_ReportServer.sql
echo SELECT * from sys.asymmetric_ksql WHERE db_id()^>4 >> %DIR_CMDS%\sp_helpcipherasym_ReportServer.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpciphersym_ReportServer.sql -o%DIR_RESULTS%\sp_helpciphersym_ReportServer.txt

echo go >> %DIR_CMDS%\sp_helpcipherasym_ReportServer.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpcipherasym_ReportServer.sql -o%DIR_RESULTS%\sp_helpcipherasym_ReportServer.txt

echo set nocount on > %DIR_CMDS%\sp_helpuser_ReportServerTempDB.sql
echo use ReportServerTempDB >> %DIR_CMDS%\sp_helpuser_ReportServerTempDB.sql
echo exec sp_helpuser >> %DIR_CMDS%\sp_helpuser_ReportServerTempDB.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpuser_ReportServerTempDB.sql -o%DIR_RESULTS%\sp_helpuser_ReportServerTempDB.txt

echo set nocount on > %DIR_CMDS%\sp_helprotect_ReportServerTempDB.sql
echo use ReportServerTempDB >> %DIR_CMDS%\sp_helprotect_ReportServerTempDB.sql
echo exec sp_helprotect >> %DIR_CMDS%\sp_helprotect_ReportServerTempDB.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprotect_ReportServerTempDB.sql -o%DIR_RESULTS%\sp_helprotect_ReportServerTempDB.txt

echo set nocount on > %DIR_CMDS%\sp_helprolemember_ReportServerTempDB.sql
echo use ReportServerTempDB >> %DIR_CMDS%\sp_helprolemember_ReportServerTempDB.sql
echo exec sp_helprolemember >> %DIR_CMDS%\sp_helprolemember_ReportServerTempDB.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprolemember_ReportServerTempDB.sql -o%DIR_RESULTS%\sp_helprolemember_ReportServerTempDB.txt

echo set nocount on > %DIR_CMDS%\sp_helpciphersym_ReportServerTempDB.sql
echo use ReportServerTempDB >> %DIR_CMDS%\sp_helpciphersym_ReportServerTempDB.sql
echo go >> %DIR_CMDS%\sp_helpciphersym_ReportServerTempDB.sql
echo SELECT * from sys.symmetric_ksql WHERE db_id()^>4 >> %DIR_CMDS%\sp_helpciphersym_ReportServerTempDB.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helprolemember_ReportServerTempDB.sql -o%DIR_RESULTS%\sp_helprolemember_ReportServerTempDB.txt

echo go >> %DIR_CMDS%\sp_helpciphersym_ReportServerTempDB.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpciphersym_ReportServerTempDB.sql -o%DIR_RESULTS%\sp_helpciphersym_ReportServerTempDB.txt

echo set nocount on > %DIR_CMDS%\sp_helpcipherasym_ReportServerTempDB.sql
echo use ReportServerTempDB >> %DIR_CMDS%\sp_helpcipherasym_ReportServerTempDB.sql
echo go >> %DIR_CMDS%\sp_helpcipherasym_ReportServerTempDB.sql
echo SELECT * from sys.asymmetric_ksql WHERE db_id()^>4 >> %DIR_CMDS%\sp_helpcipherasym_ReportServerTempDB.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpciphersym_ReportServerTempDB.sql -o%DIR_RESULTS%\sp_helpciphersym_ReportServerTempDB.txt

echo go >> %DIR_CMDS%\sp_helpcipherasym_ReportServerTempDB.sql
sqlcmd -S%server% -E -s";" -w1000 -dmaster -i%DIR_CMDS%\sp_helpcipherasym_ReportServerTempDB.sql -o%DIR_RESULTS%\sp_helpcipherasym_ReportServerTempDB.txt
