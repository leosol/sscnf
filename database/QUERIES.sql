---sucessfull logons
select
	event_id,
	event_time_utc,
	computer,
	event_summary,
	logon_type,
	CASE logon_type
		WHEN 2 THEN "Logon at keyboard/screen"
		WHEN 3 THEN "Connection to shared folder on this computer"
		WHEN 4 THEN "Scheduled task"
		WHEN 5 THEN "Service startup"
		WHEN 7 THEN "Unlock (protected by screen saver)"
		WHEN 8 THEN "!!NetworkCleartext (Logon with credentials sent in the CLEAR TEXT)"
		WHEN 9 THEN "RunAs"
		WHEN 10 THEN "RemoteInteractive (Terminal Services, Remote Desktop or Remote Assistance)"
		WHEN 11 THEN "CachedInteractive (away from the corp network)"
		ELSE "Missing type"
	END as logon_type_str,
	target_user_name as who_just_logged,
	s_user_name as account_that_requested_logon,
	target_user_name||' at '||target_domain_name||' at session with id '||target_logon_id as who_just_logged_info,
	s_user_name||' at '||s_domain_name||' at session with id '||s_logon_id as account_that_requested_logon_info
from windows_logon
where event_id in (4624, 4647)
and target_user_name not in ('UMFD-0', 'UMFD-1', 'UMFD-2', 'DWM-1', 'DWM-2')
and target_domain_name not in ('AUTORIDADE NT')
order by event_time_utc desc
--logon_type in (2)
and 


---failed logons
select
	event_id,
	event_time_utc,
	computer,
	event_summary,
	logon_type,
	CASE logon_type
		WHEN 2 THEN "Logon at keyboard/screen"
		WHEN 3 THEN "Connection to shared folder on this computer"
		WHEN 4 THEN "Scheduled task"
		WHEN 5 THEN "Service startup"
		WHEN 7 THEN "Unlock (protected by screen saver)"
		WHEN 8 THEN "!!NetworkCleartext (Logon with credentials sent in the CLEAR TEXT)"
		WHEN 9 THEN "RunAs"
		WHEN 10 THEN "RemoteInteractive (Terminal Services, Remote Desktop or Remote Assistance)"
		WHEN 11 THEN "CachedInteractive (away from the corp network)"
		ELSE "Missing type"
	END as logon_type_str,
	target_user_name as who_just_logged,
	s_user_name as account_that_requested_logon,
	target_user_name||' at '||target_domain_name||' at session with id '||target_logon_id as who_just_logged_info,
	s_user_name||' at '||s_domain_name||' at session with id '||s_logon_id as account_that_requested_logon_info
from windows_logon
where event_id in (4625)


select
	event_id,
	event_time_utc,
	computer,
	event_summary,
	logon_type,
	CASE logon_type
		WHEN 2 THEN "Logon at keyboard/screen"
		WHEN 3 THEN "Connection to shared folder on this computer"
		WHEN 4 THEN "Scheduled task"
		WHEN 5 THEN "Service startup"
		WHEN 7 THEN "Unlock (protected by screen saver)"
		WHEN 8 THEN "!!NetworkCleartext (Logon with credentials sent in the CLEAR TEXT)"
		WHEN 9 THEN "RunAs"
		WHEN 10 THEN "RemoteInteractive (Terminal Services, Remote Desktop or Remote Assistance)"
		WHEN 11 THEN "CachedInteractive (away from the corp network)"
		ELSE "Missing type"
	END as logon_type_str,
	target_user_name as who_just_logged,
	s_user_name as account_that_requested_logon,
	target_user_name||' at '||target_domain_name||' at session with id '||target_logon_id as who_just_logged_info,
	s_user_name||' at '||s_domain_name||' at session with id '||s_logon_id as account_that_requested_logon_info
from windows_logon
where event_id in (4648)
and target_user_name not in ('UMFD-0', 'UMFD-1', 'UMFD-2', 'DWM-1', 'DWM-2')