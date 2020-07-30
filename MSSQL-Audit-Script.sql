-- ------------------------------------------------------------------------------------------------------------------------------------------------------------
--  Basic MSSQL security assessment script
--  To run this SQL script you need to do the following 3 steps:
--  Step 1: Create a simple ".bat" file containing the following commands:
--          sqlcmd -s";" -w1000 -dmaster -iMSSQL-Audit-Script.sql -oresults.bat -Sserver-name\Instance-name
--          results.bat
--  Step 2: Start a cmd console with a Windows account that has DBA privileges (i.e. runas /user:Domain\account cmd) on the Windows server hosting the database
--  Step 3. Run the ".bat" script 
-- ------------------------------------------------------------------------------------------------------------------------------------------------------------

print "@echo on"
print "@echo off"
print "set /p server= Type in the server and instance name (such as : server-name\instance-name):
print "echo."
print "set /p analysis= Please type in a name for the current analysis, do not include spaces:"
print "echo."
print "echo Creating Output directory"
print "mkdir Output-%analysis%"
print "mkdir Output-%analysis%\commands"
print "mkdir Output-%analysis%\results"

print "set DIR_RESULTS=Output-%analysis%\results"
print "set DIR_CMDS=Output-%analysis%\commands"

-- Gathering information regarding the local windows system
print "net accounts > %DIR_RESULTS%\windows-local-account-policy.txt"
print "net start > %DIR_RESULTS%\windows-services.txt"
print "net user > %DIR_RESULTS%\windows-local-users.txt"
print "net localgroup > %DIR_RESULTS%\windows-local-groups.txt"

print "@echo on"

declare @query varchar(255)
declare @temp varchar(255)

-- Information regarding the Server name, MSQL Version and the current time..
set nocount on
print "echo set nocount on > %DIR_CMDS%\dbnm.sql"
print "echo select @@servername, @@version, getdate() >> %DIR_CMDS%\dbnm.sql"
print "echo go >> %DIR_CMDS%\dbnm.sql"
print @temp
select @temp = "sqlcmd -S%server% -E  -s"";"" -w1000 -dmaster -i%DIR_CMDS%\dbnm.sql -o%DIR_RESULTS%\dbnm.txt"
print @temp
go

declare @query varchar(255)
declare @temp varchar(255)
-- xp_loginconfig : reports the login and audit security configuration of MSQL Server
set nocount on
print "echo set nocount on > %DIR_CMDS%\audit.sql"
print "echo exec xp_loginconfig >> %DIR_CMDS%\audit.sql"
print "echo go >> %DIR_CMDS%\audit.sql"
print @temp
select @temp = "sqlcmd -S%server% -E  -s"";"" -w1000 -dmaster -i%DIR_CMDS%\audit.sql -o%DIR_RESULTS%\audit.txt"
print @temp
go

declare @query varchar(255)
declare @temp varchar(255)
-- sp_helpdb : reports information regarding all databases (name/size/owner/date of creation/status)
set nocount on
print "echo set nocount on > %DIR_CMDS%\sphelpdb.sql"
print "echo exec sp_helpdb>> %DIR_CMDS%\sphelpdb.sql"
print "echo go >> %DIR_CMDS%\sphelpdb.sql"
print @temp
select @temp = "sqlcmd -S%server% -E  -s"";"" -w1000 -dmaster -i%DIR_CMDS%\sphelpdb.sql -o%DIR_RESULTS%\sphelpdb.txt"
print @temp
go

-- Tests for MSDB and Master Database

declare @query varchar(255)
declare @temp varchar(255)

-- Retrieve accounts that had not their passwords changed since 60 days
set nocount on
print "echo set nocount on > %DIR_CMDS%\dormantpassword_master.sql"
print "echo use master >> %DIR_CMDS%\dormantpassword_master.sql"
print "echo go >> %DIR_CMDS%\dormantpassword_master.sql"
print "echo select sid, name, type_desc, is_disabled, modify_date from sys.server_principals where datediff(day, modify_date, getdate()) ^> 60 order by modify_date >> %DIR_CMDS%\dormantpassword_master.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\dormantpassword_master.sql"
print @temp
select @temp = "sqlcmd -S%server% -E  -s"";"" -w1000 -dmaster -i%DIR_CMDS%\dormantpassword_master.sql -o%DIR_RESULTS%\dormantpassword_master.txt"
print @temp
go

-- Get SQL Server Replication options
declare @query varchar(255)
declare @temp varchar(255)
set nocount on
print "echo set nocount on > %DIR_CMDS%\MSreplication_options.sql"
print "echo use master >> %DIR_CMDS%\MSreplication_options.sql"
print "echo go >> %DIR_CMDS%\MSreplication_options.sql"
print "echo SELECT * from MSreplication_options >> %DIR_CMDS%\MSreplication_options.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\MSreplication_options.sql"
print @temp
select @temp = "sqlcmd -S%server% -E    -s"";"" -w500 -dmaster -i%DIR_CMDS%\MSreplication_options.sql -o%DIR_RESULTS%\MSreplication_options.txt"
print @temp
go

-- Get the list of every alerts defined on SQL Server
declare @query varchar(255)
declare @temp varchar(255)
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysalerts.sql"
print "echo use msdb >> %DIR_CMDS%\sysalerts.sql"
print "echo go >> %DIR_CMDS%\sysalerts.sql"
print "echo SELECT * from sysalerts >> %DIR_CMDS%\sysalerts.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysalerts.sql"
print @temp
select @temp = "sqlcmd -S%server% -E    -s"";"" -w500 -dmsdb -i%DIR_CMDS%\sysalerts.sql -o%DIR_RESULTS%\sysalerts.txt"
print @temp
go

-- Get sys.assemblies permissions
declare @query varchar(255)
declare @temp varchar(255)
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysassemblies.sql"
print "echo use master >> %DIR_CMDS%\sysassemblies.sql"
print "echo go >> %DIR_CMDS%\sysassemblies.sql"
print "echo SELECT name, permission_set_desc from sys.assemblies where is_user_defined = 1 >> %DIR_CMDS%\sysassemblies.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysassemblies.sql"
print @temp
select @temp = "sqlcmd -S%server% -E    -s"";"" -w500 -dmaster -i%DIR_CMDS%\sysassemblies.sql -o%DIR_RESULTS%\sysassemblies.txt"
print @temp
go

-- Get the name of the database files used for each SQL Server database
declare @query varchar(255)
declare @temp varchar(255)
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysaltfiles.sql"
print "echo use master >> %DIR_CMDS%\sysaltfiles.sql"
print "echo go >> %DIR_CMDS%\sysaltfiles.sql"
print "echo SELECT * from sys.master_files >> %DIR_CMDS%\sysaltfiles.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysaltfiles.sql"
print @temp
select @temp = "sqlcmd -S%server% -E    -s"";"" -w500 -dmaster -i%DIR_CMDS%\sysaltfiles.sql -o%DIR_RESULTS%\sysaltfiles.txt"
print @temp
go

-- Retrieve information on categories (used by SQL Server to organize jobs, operators, alerts)
declare @query varchar(255)
declare @temp varchar(255)
set nocount on
print "echo set nocount on > %DIR_CMDS%\syscategories.sql"
print "echo use msdb >> %DIR_CMDS%\syscategories.sql"
print "echo go >> %DIR_CMDS%\syscategories.sql"
print "echo SELECT * from syscategories >> %DIR_CMDS%\syscategories.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\syscategories.sql"
print @temp
select @temp = "sqlcmd -S%server% -E    -s"";"" -w500 -dmsdb -i%DIR_CMDS%\syscategories.sql -o%DIR_RESULTS%\syscategories.txt"
print @temp
go

declare @query varchar(255)
declare @temp varchar(255)
-- sysconfigures contains the configuration options defined before the most recent MSQL Server startup plus any dynamic 
-- configuration options set since then.
-- sys.configurations contains SQL2000 sysconfigures and syscurconfigs
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysconfigures.sql"
print "echo use master >> %DIR_CMDS%\sysconfigures.sql"
print "echo go >> %DIR_CMDS%\sysconfigures.sql"
print "echo SELECT * from sys.configurations >> %DIR_CMDS%\sysconfigures.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysconfigures.sql"
print @temp
select @temp = "sqlcmd -S%server% -E    -s"";"" -w500 -dmaster -i%DIR_CMDS%\sysconfigures.sql -o%DIR_RESULTS%\sysconfigures.txt"
print @temp
go

declare @query varchar(255)
declare @temp varchar(255)
-- Get the list of every database hosted on the SQL Server
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysdatabases.sql"
print "echo use master >> %DIR_CMDS%\sysdatabases.sql"
print "echo go >> %DIR_CMDS%\sysdatabases.sql"
print "echo SELECT * from sys.databases >> %DIR_CMDS%\sysdatabases.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysdatabases.sql"
print @temp
select @temp = "sqlcmd -S%server% -E    -s"";"" -w500 -dmaster -i%DIR_CMDS%\sysdatabases.sql -o%DIR_RESULTS%\sysdatabases.txt"
print @temp
go


-- Contains one row for each disk backup file, tape backup file, and database file
declare @query varchar(255)
declare @temp varchar(255)
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysdevices.sql"
print "echo use master >> %DIR_CMDS%\sysdevices.sql"
print "echo go >> %DIR_CMDS%\sysdevices.sql"
print "echo SELECT * from sys.backup_devices >> %DIR_CMDS%\sysdevices.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysdevices.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmaster -i%DIR_CMDS%\sysdevices.sql -o%DIR_RESULTS%\sysdevices.txt"
print @temp
go

declare @query varchar(255)
declare @temp varchar(255)
-- Contains information about the execution of scheduled jobs by SQL Server Agent.
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysjobhistory.sql"
print "echo use msdb >> %DIR_CMDS%\sysjobhistory.sql"
print "echo go >> %DIR_CMDS%\sysjobhistory.sql"
print "echo SELECT * from sysjobhistory >> %DIR_CMDS%\sysjobhistory.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysjobhistory.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmsdb -i%DIR_CMDS%\sysjobhistory.sql -o%DIR_RESULTS%\sysjobhistory.txt"
print @temp
go

declare @query varchar(255)
declare @temp varchar(255)
-- Stores the information for each scheduled job to be executed by SQL Server Agent
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysjobs.sql"
print "echo use msdb >> %DIR_CMDS%\sysjobs.sql"
print "echo go >> %DIR_CMDS%\sysjobs.sql"
print "echo SELECT * from sysjobs >> %DIR_CMDS%\sysjobs.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysjobs.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmsdb -i%DIR_CMDS%\sysjobs.sql -o%DIR_RESULTS%\sysjobs.txt"
print @temp
go

declare @query varchar(255)
declare @temp varchar(255)
-- Contains schedule information for jobs to be executed by SQL Server Agent
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysjobschedules.sql"
print "echo use msdb >> %DIR_CMDS%\sysjobschedules.sql"
print "echo go >> %DIR_CMDS%\sysjobschedules.sql"
print "echo SELECT * from sysjobschedules >> %DIR_CMDS%\sysjobschedules.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysjobschedules.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmsdb -i%DIR_CMDS%\sysjobschedules.sql -o%DIR_RESULTS%\sysjobschedules.txt"
print @temp
go

declare @query varchar(255)
declare @temp varchar(255)
-- Stores the association or relationship of a particular job with one or more target servers
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysjobservers.sql"
print "echo use msdb >> %DIR_CMDS%\sysjobservers.sql"
print "echo go >> %DIR_CMDS%\sysjobservers.sql"
print "echo SELECT * from sysjobservers >> %DIR_CMDS%\sysjobservers.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysjobservers.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmsdb -i%DIR_CMDS%\sysjobservers.sql -o%DIR_RESULTS%\sysjobservers.txt"
print @temp
go

-- Contains the information for each step in a job to be executed by SQL Server Agent
declare @query varchar(255)
declare @temp varchar(255)
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysjobsteps.sql"
print "echo use msdb >> %DIR_CMDS%\sysjobsteps.sql"
print "echo go >> %DIR_CMDS%\sysjobsteps.sql"
print "echo SELECT * from sysjobsteps >> %DIR_CMDS%\sysjobsteps.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysjobsteps.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmsdb -i%DIR_CMDS%\sysjobsteps.sql -o%DIR_RESULTS%\sysjobsteps.txt"
print @temp
go

-- Contains one row for each user and password mapping for the specified linked server
declare @query varchar(255)
declare @temp varchar(255)
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysoledbusers.sql"
print "echo use msdb >> %DIR_CMDS%\sysoledbusers.sql"
print "echo go >> %DIR_CMDS%\sysoledbusers.sql"
print "echo SELECT * from sysoledbusers >> %DIR_CMDS%\sysoledbusers.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysoledbusers.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmsdb -i%DIR_CMDS%\sysoledbusers.sql -o%DIR_RESULTS%\sysoledbusers.txt"
print @temp
go


declare @query varchar(255)
declare @temp varchar(255)
-- Contains one row for each server role. 
set nocount on
print "echo set nocount on > %DIR_CMDS%\syssvrroles.sql"
print "echo use master >> %DIR_CMDS%\syssvrroles.sql"
print "echo go >> %DIR_CMDS%\syssvrroles.sql"
print "echo SELECT pr.name, pr.is_disabled, pr.is_fixed_role, pr.create_date, pr.modify_date, pr.default_database_name, owner.name AS owner_name FROM sys.server_principals AS pr JOIN sys.server_principals AS owner ON pr.owning_principal_id = owner.principal_id WHERE pr.type = 'R' ORDER BY name >> %DIR_CMDS%\syssvrroles.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\syssvrroles.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmaster -i%DIR_CMDS%\syssvrroles.sql -o%DIR_RESULTS%\syssvrroles.txt"
print @temp
go

declare @query varchar(255)
declare @temp varchar(255)
-- Contains one row for each member of a server role
set nocount on
print "echo set nocount on > %DIR_CMDS%\syssvrrolemembers.sql"
print "echo use master >> %DIR_CMDS%\syssvrrolemembers.sql"
print "echo go >> %DIR_CMDS%\syssvrrolemembers.sql"
print "echo SELECT role.name AS role_name, member.name AS member_name from sys.server_role_members JOIN sys.server_principals AS role ON sys.server_role_members.role_principal_id = role.principal_id JOIN sys.server_principals AS member ON sys.server_role_members.member_principal_id = member.principal_id >> %DIR_CMDS%\syssvrrolemembers.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\syssvrrolemembers.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmaster -i%DIR_CMDS%\syssvrrolemembers.sql -o%DIR_RESULTS%\syssvrrolemembers.txt"
print @temp
go

declare @query varchar(255)
declare @temp varchar(255)
-- Contains one row for each permission granted to a server role, does not show permissions associated to fixed server roles. 
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysserverpermissions.sql"
print "echo use master >> %DIR_CMDS%\syserverpermissions.sql"
print "echo go >> %DIR_CMDS%\syserverpermissions.sql"
print "echo SELECT pr.name, pe.state_desc, pe.permission_name FROM sys.server_principals AS pr JOIN sys.server_permissions AS pe ON pe.grantee_principal_id = pr.principal_id WHERE pr.type = 'R' ORDER BY name >> %DIR_CMDS%\sysserverpermissions.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysserverpermissions.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmaster -i%DIR_CMDS%\sysserverpermissions.sql -o%DIR_RESULTS%\sysserverpermissions.txt"
print @temp
go


declare @query varchar(255)
declare @temp varchar(255)
-- Contains one row for each login account. Password hash are stored in a dedicated file
set nocount on
print "echo set nocount on > %DIR_CMDS%\syslogins.sql"
print "echo use master >> %DIR_CMDS%\syslogins.sql"
print "echo go >> %DIR_CMDS%\syslogins.sql"
print "echo SELECT createdate, updatedate, name, dbname, password, denylogin, hasaccess, isntname, isntgroup, isntuser, sysadmin, securityadmin, bulkadmin, serveradmin, setupadmin, processadmin, diskadmin, dbcreator, loginname  from syslogins >> %DIR_CMDS%\syslogins.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\syslogins.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmaster -i%DIR_CMDS%\syslogins.sql -o%DIR_RESULTS%\syslogins.txt"
print @temp
go

declare @query varchar(255)
declare @temp varchar(255)
-- Contains mainly the password hash of the users
set nocount on
print "echo set nocount on > %DIR_CMDS%\syssqllogins.sql"
print "echo use master >> %DIR_CMDS%\syssqllogins.sql"
print "echo go >> %DIR_CMDS%\syssqllogins.sql"
print "echo SELECT * from sys.sql_logins >> %DIR_CMDS%\syssqllogins.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\syssqllogins.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmaster -i%DIR_CMDS%\syssqllogins.sql -o%DIR_RESULTS%\password_hashs.txt"
print @temp
go


declare @query varchar(255)
declare @temp varchar(255)
-- Contains one row for each notification
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysnotifications.sql"
print "echo use msdb >> %DIR_CMDS%\sysnotifications.sql"
print "echo go >> %DIR_CMDS%\sysnotifications.sql"
print "echo SELECT * from sysnotifications >> %DIR_CMDS%\sysnotifications.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysnotifications.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmsdb -i%DIR_CMDS%\sysnotifications.sql -o%DIR_RESULTS%\sysnotifications.txt"
print @temp
go

-- Contains one row for each operator.
declare @query varchar(255)
declare @temp varchar(255)
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysoperators.sql"
print "echo use msdb >> %DIR_CMDS%\sysoperators.sql"
print "echo go >> %DIR_CMDS%\sysoperators.sql"
print "echo SELECT * from sysoperators >> %DIR_CMDS%\sysoperators.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysoperators.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmsdb -i%DIR_CMDS%\sysoperators.sql -o%DIR_RESULTS%\sysoperators.txt"
print @temp
go

declare @query varchar(255)
declare @temp varchar(255)
-- The sysprocesses table holds information about processes running on Microsoft SQL Server. These processes can be client processes or system processes
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysprocesses.sql"
print "echo use master >> %DIR_CMDS%\sysprocesses.sql"
print "echo go >> %DIR_CMDS%\sysprocesses.sql"
print "echo SELECT * from sysprocesses >> %DIR_CMDS%\sysprocesses.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysprocesses.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmaster -i%DIR_CMDS%\sysprocesses.sql -o%DIR_RESULTS%\sysprocesses.txt"
print @temp
go

declare @query varchar(255)
declare @temp varchar(255)
-- Contains one row for each remote user allowed to call remote stored procedures on Microsoft SQL Server 
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysremotelogins.sql"
print "echo use master >> %DIR_CMDS%\sysremotelogins.sql"
print "echo go >> %DIR_CMDS%\sysremotelogins.sql"
print "echo SELECT * from sys.remote_logins >> %DIR_CMDS%\sysremotelogins.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysremotelogins.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmaster -i%DIR_CMDS%\sysremotelogins.sql -o%DIR_RESULTS%\sysremotelogins.txt"
print @temp
go

declare @query varchar(255)
declare @temp varchar(255)
-- Contains one row for each server that Microsoft SQL Server can access as an OLE DB data source
set nocount on
print "echo set nocount on > %DIR_CMDS%\sysservers.sql"
print "echo use master >> %DIR_CMDS%\sysservers.sql"
print "echo go >> %DIR_CMDS%\sysservers.sql"
print "echo SELECT * from sys.servers >> %DIR_CMDS%\sysservers.sql"
print @temp
select @temp = "echo go >> " + "%DIR_CMDS%\sysservers.sql"
print @temp
select @temp = "sqlcmd -S%server% -E -s"";"" -w500 -dmaster -i%DIR_CMDS%\sysservers.sql -o%DIR_RESULTS%\sysservers.txt"
print @temp
go


-- Tests for each database
declare db_cursor cursor
	for select name from master.dbo.sysdatabases
	for read only
go

set nocount on
open db_cursor

declare @mycounter  int
declare @myrowcount  int
declare @mydbname  varchar(255)
declare @sqlquery varchar(255)
declare @queryname varchar(100)
declare @temp varchar(255)

select @myrowcount = (select count(name) from master.dbo.sysdatabases)

select @mycounter = 1

while @mycounter <= @myrowcount

begin
	fetch db_cursor into @mydbname

	-- sp_helpuser : reports human-reading information about user access on database
	select @queryname = "sp_helpuser"
	print "echo set nocount on > %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print "echo use "+@mydbname+" >> %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	select @sqlquery = "exec "+@queryname+""
	select @temp = "echo "+@sqlquery+" >> %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print @temp
	select @temp = "sqlcmd -S%server% -E -s"";"" -w1000 -dmaster -i%DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"+" -o%DIR_RESULTS%\"+@queryname+"_"+@mydbname+".txt"
	print @temp
	
	-- sp_helprotect : reports human-reading information about user permissions on objects
	select @queryname = "sp_helprotect"
	print "echo set nocount on > %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print "echo use "+@mydbname+" >> %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	select @sqlquery = "exec "+@queryname+""
	select @temp = "echo "+@sqlquery+" >> %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print @temp
	select @temp = "sqlcmd -S%server% -E -s"";"" -w1000 -dmaster -i%DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"+" -o%DIR_RESULTS%\"+@queryname+"_"+@mydbname+".txt"
	print @temp

	-- sp_helprolemember : returns human-reading information on members of roles in the current database
	select @queryname = "sp_helprolemember"
	print "echo set nocount on > %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print "echo use "+@mydbname+" >> %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	select @sqlquery = "exec "+@queryname+""
	select @temp = "echo "+@sqlquery+" >> %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print @temp
	select @temp = "sqlcmd -S%server% -E -s"";"" -w1000 -dmaster -i%DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"+" -o%DIR_RESULTS%\"+@queryname+"_"+@mydbname+".txt"
	print @temp
	
	-- sp_helpciphersym : returns human-reading cypher algorithms in the current database for user-defined db
	select @queryname = "sp_helpciphersym"
	print "echo set nocount on > %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print "echo use "+@mydbname+" >> %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print "echo go >> %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print "echo SELECT * from sys.symmetric_ksql WHERE db_id()^>4 >> %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print @temp
	select @temp = "echo go >> %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print @temp
	select @temp = "sqlcmd -S%server% -E -s"";"" -w1000 -dmaster -i%DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"+" -o%DIR_RESULTS%\"+@queryname+"_"+@mydbname+".txt"
	print @temp
	
	-- sp_helpcipherasym : returns human-reading cypher algorithms in the current database for user-defined db
	select @queryname = "sp_helpcipherasym"
	print "echo set nocount on > %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print "echo use "+@mydbname+" >> %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print "echo go >> %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print "echo SELECT * from sys.asymmetric_ksql WHERE db_id()^>4 >> %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print @temp
	select @temp = "echo go >> %DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"
	print @temp
	select @temp = "sqlcmd -S%server% -E -s"";"" -w1000 -dmaster -i%DIR_CMDS%\"+@queryname+"_"+@mydbname+".sql"+" -o%DIR_RESULTS%\"+@queryname+"_"+@mydbname+".txt"
	print @temp

	select @mycounter=@mycounter+1
	continue
end

close db_cursor
deallocate db_cursor

-- collect data on all the traces being performed
declare db_cursor cursor 
	for select distinct traceid from :: fn_trace_getinfo(0)
	for read only
go

set nocount on
open db_cursor

declare @mycounter  int
declare @myrowcount  int
declare @mytraceid  varchar(255)
declare @temp varchar(255)

select @myrowcount = (select count(distinct traceid) from :: fn_trace_getinfo(0))

select @mycounter = 1

while @mycounter <= @myrowcount
begin
	fetch db_cursor into @mytraceid
  	select @temp = "echo select * from :: fn_trace_geteventinfo("+@mytraceid+") > %DIR_CMDS%\trace_"+@mytraceid+".sql"
	print @temp
	select @temp = "sqlcmd -S%server% -E -E -s"";"" -w1000 -dmaster -i%DIR_CMDS%\trace_"+@mytraceid+".sql -o%DIR_RESULTS%\trace_"+@mytraceid+".txt"
	print @temp	
	-- Check if sql profiler is used
	select @temp = "echo select * from :: fn_trace_getfilterinfo("+@mytraceid+") > %DIR_CMDS%\profiler_"+@mytraceid+".sql"
	print @temp
	select @temp = "sqlcmd -S%server% -E -E -s"";"" -w1000 -dmaster -i%DIR_CMDS%\profiler_"+@mytraceid+".sql -o%DIR_RESULTS%\profiler_"+@mytraceid+".txt"
	print @temp	

	select @mycounter=@mycounter+1
	continue
end

close db_cursor
deallocate db_cursor

print @temp
