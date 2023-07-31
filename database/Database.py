import sqlite3
import hashlib
from sqlite3 import Error

class Database:
    def init(self, dbname):
        if dbname is None:
            dbname = 'winevtx.db'
        self.conn = sqlite3.connect(dbname)
        self.c = self.conn.cursor()
        self.create_database()
        self.create_views()

    def close(self):
        self.c.close()
        self.conn.close()

    def create_database(self):
        sql = 'create table if not exists windows_received_rdp_logon (id INTEGER PRIMARY KEY, ' \
              ' event_id TEXT, ' \
              ' event_time_utc TEXT, '\
              ' event_summary TEXT, ' \
              ' event_record_no TEXT, ' \
              ' computer TEXT, ' \
              ' process_id TEXT, ' \
              ' thread_id TEXT, ' \
              ' param1_user TEXT, ' \
              ' param2_domain TEXT, ' \
              ' param3_IP_addr TEXT )'
        self.c.execute(sql)
        sql = 'create table if not exists windows_logon (id INTEGER PRIMARY KEY, ' \
              ' event_id TEXT, ' \
              ' event_time_utc TEXT, '\
              ' event_summary TEXT, ' \
              ' event_record_no TEXT, ' \
              ' computer TEXT, ' \
              ' process_id TEXT, ' \
              ' thread_id TEXT, ' \
              ' s_user_id TEXT, ' \
              ' s_user_name TEXT, ' \
              ' s_domain_name TEXT, ' \
              ' s_logon_id TEXT, ' \
              ' target_user_sid TEXT, ' \
              ' target_user_name TEXT, ' \
              ' target_domain_name TEXT, ' \
              ' target_logon_id TEXT, ' \
              ' logon_type TEXT, ' \
              ' logon_process_name TEXT, ' \
              ' auth_pkg_name TEXT, ' \
              ' workstation_name TEXT, ' \
              ' logon_guid TEXT, ' \
              ' transmitted_services TEXT, ' \
              ' lm_package_name TEXT, ' \
              ' key_length TEXT, ' \
              ' data_process_id TEXT, ' \
              ' data_process_name TEXT, ' \
              ' ip_addr TEXT, ' \
              ' ip_port TEXT, ' \
              ' impersonation_level TEXT, ' \
              ' restricted_admin_mode TEXT, ' \
              ' target_outbound_username TEXT, ' \
              ' target_outbound_domain TEXT, ' \
              ' virtual_account TEXT, ' \
              ' target_linked_logon TEXT, ' \
              ' elevated_token TEXT, ' \
              ' process_info TEXT )'
        self.c.execute(sql)
        self.conn.commit()
        sql = 'create table if not exists windows_received_tcp_udp_connections (id INTEGER PRIMARY KEY, ' \
              ' event_id TEXT, ' \
              ' event_time_utc TEXT, ' \
              ' event_summary TEXT, ' \
              ' event_record_no TEXT, ' \
              ' computer TEXT, ' \
              ' process_id TEXT, ' \
              ' thread_id TEXT, ' \
              ' conn_type TEXT, ' \
              ' client_ip TEXT )'
        self.c.execute(sql)
        self.conn.commit()
        sql = 'create table if not exists received_rdp_logon_logoff_and_gui_info (id INTEGER PRIMARY KEY, ' \
              ' event_id TEXT, ' \
              ' event_time_utc TEXT, '\
              ' event_summary TEXT, ' \
              ' event_record_no TEXT, ' \
              ' computer TEXT, ' \
              ' process_id TEXT, ' \
              ' thread_id TEXT, ' \
              ' provider TEXT, ' \
              ' level TEXT, ' \
              ' channel TEXT, ' \
              ' security_user_id TEXT, ' \
              ' event_data_0 TEXT, ' \
              ' event_data_1 TEXT, ' \
              ' event_data_2 TEXT, ' \
              ' event_data_3 TEXT, ' \
              ' param1_user TEXT, ' \
              ' param2_session_id TEXT, ' \
              ' param3_address TEXT, ' \
              ' param4_session TEXT, ' \
              ' param5_reason TEXT, ' \
              ' param5_reason_str TEXT )'
        self.c.execute(sql)
        sql = 'create table if not exists made_rdp_outgoing (id INTEGER PRIMARY KEY, ' \
              ' event_id TEXT, ' \
              ' event_time_utc TEXT, ' \
              ' event_summary TEXT, ' \
              ' event_record_no TEXT, ' \
              ' computer TEXT, ' \
              ' process_id TEXT, ' \
              ' thread_id TEXT, ' \
              ' provider TEXT, ' \
              ' level TEXT, ' \
              ' channel TEXT, ' \
              ' security_user_id TEXT, ' \
              ' event_data_0 TEXT, ' \
              ' event_data_1 TEXT, ' \
              ' event_data_2 TEXT, ' \
              ' event_data_3 TEXT, ' \
              ' event_data_4 TEXT, ' \
              ' event_data_5 TEXT )'
        self.c.execute(sql)
        sql = 'create table if not exists kaspersky_endpoint_events (id INTEGER PRIMARY KEY, ' \
              ' event_id TEXT, ' \
              ' event_time_utc TEXT, ' \
              ' event_summary TEXT, ' \
              ' event_record_no TEXT, ' \
              ' computer TEXT, ' \
              ' provider TEXT, ' \
              ' level TEXT, ' \
              ' channel TEXT, ' \
              ' security_user_id TEXT, ' \
              ' event_data_0 TEXT, ' \
              ' event_data_1 TEXT, ' \
              ' event_data_2 TEXT, ' \
              ' event_data_3 TEXT, ' \
              ' threat_param_0 TEXT, ' \
              ' threat_param_1 TEXT, ' \
              ' threat_param_2 TEXT, ' \
              ' threat_param_3 TEXT, ' \
              ' threat_param_4 TEXT, ' \
              ' threat_param_5 TEXT, ' \
              ' threat_param_6 TEXT, ' \
              ' threat_param_7 TEXT, ' \
              ' threat_param_8 TEXT, ' \
              ' threat_param_9 TEXT, ' \
              ' threat_param_10 TEXT, ' \
              ' threat_param_11 TEXT, ' \
              ' threat_param_12 TEXT, ' \
              ' threat_param_13 TEXT, ' \
              ' threat_param_14 TEXT, ' \
              ' threat_param_15 TEXT, ' \
              ' threat_param_16 TEXT, ' \
              ' threat_param_17 TEXT, ' \
              ' threat_param_18 TEXT, ' \
              ' threat_param_19 TEXT )'
        self.c.execute(sql)
        sql = 'create table if not exists power_shell_script_logging (id INTEGER PRIMARY KEY, ' \
              ' event_id TEXT, ' \
              ' event_time_utc TEXT, ' \
              ' event_summary TEXT, ' \
              ' event_record_no TEXT, ' \
              ' computer TEXT, ' \
              ' process_id TEXT, ' \
              ' thread_id TEXT, ' \
              ' provider TEXT, ' \
              ' level TEXT, ' \
              ' channel TEXT, ' \
              ' security_user_id TEXT, ' \
              ' event_data_0 TEXT, ' \
              ' event_data_1 TEXT, ' \
              ' event_data_2 TEXT, ' \
              ' event_data_3 TEXT, ' \
              ' event_data_4 TEXT, ' \
              ' event_data_5 TEXT, ' \
              ' event_data_6 TEXT, ' \
              ' event_data_7 TEXT, ' \
              ' event_data_8 TEXT, ' \
              ' event_data_9 TEXT, ' \
              ' event_data_10 TEXT, ' \
              ' event_data_11 TEXT, ' \
              ' event_data_12 TEXT, ' \
              ' event_data_13 TEXT, ' \
              ' event_data_14 TEXT, ' \
              ' event_data_15 TEXT, ' \
              ' event_data_16 TEXT, ' \
              ' event_data_17 TEXT, ' \
              ' event_data_18 TEXT, ' \
              ' event_data_19 TEXT, ' \
              ' script_block_id TEXT, ' \
              ' script_block_text TEXT, ' \
              ' script_msg_number TEXT, ' \
              ' script_msg_total TEXT, ' \
              ' script_path TEXT, ' \
              ' script_session_id TEXT, ' \
              ' possible_command_in_str TEXT )'
        self.c.execute(sql)
        sql = "drop table if exists derived_powershell_script_blocks"
        self.c.execute(sql)
        sql = 'create table if not exists derived_powershell_script_blocks (id INTEGER PRIMARY KEY, ' \
              ' event_id TEXT, ' \
              ' script_start TEXT, ' \
              ' event_summary TEXT, ' \
              ' computer TEXT, ' \
              ' script_block_id TEXT, ' \
              ' script_hash TEXT, ' \
              ' script_msg_total TEXT, ' \
              ' script_block_assembled TEXT )'
        self.c.execute(sql)
        sql = 'create table if not exists symantec_endpoint_events (id INTEGER PRIMARY KEY, ' \
              ' event_id TEXT, ' \
              ' event_time_utc TEXT, ' \
              ' event_summary TEXT, ' \
              ' event_record_no TEXT, ' \
              ' computer TEXT, ' \
              ' provider TEXT, ' \
              ' level TEXT, ' \
              ' channel TEXT, ' \
              ' security_user_id TEXT, ' \
              ' event_data_0 TEXT, ' \
              ' event_data_1 TEXT, ' \
              ' event_data_2 TEXT, ' \
              ' event_data_3 TEXT )'
        self.c.execute(sql)

    def create_views(self):
        sql = """create view if not exists vw_summary_received_tcp_udp_connections
                as
                select 
                    substr(event_time_utc, 0, 11) as dt_event,
                    event_summary, 
                    computer, 
                    conn_type, 
                    client_ip,
                    count(*) as qtd
                from windows_received_tcp_udp_connections
                group by 1,2,3,4,5 
                order by dt_event desc"""
        self.c.execute(sql)
        sql = """create view if not exists vw_summary_received_rdp_logon_logoff_and_gui_info as 
            select 
                substr(event_time_utc, 0, 11) as dt_event,
                event_summary, 
                computer, 
                provider, 
                param1_user,
                param3_address,
                count(*) as qtd
            from received_rdp_logon_logoff_and_gui_info
            group by 1,2,3,4,5,6 
            order by dt_event desc"""
        self.c.execute(sql)
        sql = """create view if not exists vw_summary_made_rdp_outgoing as 
            select 
                substr(event_time_utc, 0, 11) as dt_event,
                event_summary, 
                computer, 
                provider, 
                event_data_0,
                event_data_1,
                event_data_2, 
                count(*) as qtd
            from made_rdp_outgoing
            group by 1,2,3,4,5,6,7 
            order by dt_event desc"""
        self.c.execute(sql)
        sql = """create view if not exists vw_summary_windows_received_rdp_logon as 
            select 
                substr(event_time_utc, 0, 11) as dt_event,
                event_summary, 
                computer, 
                param1_user, 
                param2_domain,
                param3_IP_addr,
                count(*) as qtd
            from windows_received_rdp_logon
            group by 1,2,3,4,5,6 
            order by dt_event desc"""
        self.c.execute(sql)
        sql = """create view if not exists vw_summary_windows_logon as 
            select 
                substr(event_time_utc, 0, 11) as dt_event,
                event_id,
                event_summary, 
                computer, 
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
                ip_addr,
                target_user_name as who_just_logged,
                s_user_name as account_that_requested_logon,
                count(*) as qtd,
				min(substr(event_time_utc, 12, 5)) as min_time,
				max(substr(event_time_utc, 12, 5)) as max_time
            from windows_logon
            where target_user_name not in ('UMFD-0', 'UMFD-1', 'UMFD-2', 'UMFD-3', 'UMFD-4', 'UMFD-5', 'DWM-0', 'DWM-1', 'DWM-2', 'DWM-3', 'DWM-4', 'DWM-5')
            and ( target_domain_name not in ('AUTORIDADE NT') or target_domain_name not in ('NT AUTHORITY'))
            group by 1,2,3,4,5,6,7,8,9
            order by dt_event desc"""
        self.c.execute(sql)
        sql = """create view if not exists vw_summary_kaspersky_endpoint_events as
            select 
                substr(event_time_utc, 0, 11) as dt_event,
                event_summary, 
                computer, 
                count(*) as qtd
            from kaspersky_endpoint_events
            group by 1,2,3
            order by dt_event desc"""
        self.c.execute(sql)
        sql = """create view if not exists vw_summary_symantec_endpoint_events as
                    select 
                        substr(event_time_utc, 0, 11) as dt_event,
                        event_summary, 
                        computer, 
                        count(*) as qtd
                    from symantec_endpoint_events
                    group by 1,2,3
                    order by dt_event desc"""
        self.c.execute(sql)
        sql = """create view if not exists vw_summary_powershell_web_access
                as
                select
                    substr(event_time_utc, 0, 11) as dt_event,
                    event_id,
                    event_summary, 
                    computer,
                    count(*) as qtd	
                from power_shell_script_logging
                where channel = 'Microsoft-Windows-PowerShellWebAccess/Operational'
                group by 1,2,3
                    order by dt_event desc"""
        self.c.execute(sql)
        sql = """create view if not exists vw_powershell_web_access_user_target_node
                as
                select * from power_shell_script_logging
                where channel = 'Microsoft-Windows-PowerShellWebAccess/Operational'
                    and event_data_0 = 'UserName'
                    and event_data_2 = 'TargetNode'
                order by
                    event_time_utc desc"""
        self.c.execute(sql)
        sql = """create view if not exists vw_powershell_script_blocks
                as
                select 
                    event_id,
                    event_summary,
                    computer,
                    script_block_id,
                    script_msg_total,
                    count(distinct(script_msg_number)) as qtd_items,
                    min(event_time_utc) script_start,
                    max(event_time_utc) script_end
                from power_shell_script_logging
                where 
                    length(script_block_id) > 10
                group by 1,2,3,4,5
                order by 7 desc"""
        self.c.execute(sql)
        sql = """create view if not exists vw_powershell_script_paths
                as
                select * from power_shell_script_logging
                where length(script_path) > 10
                order by
                    event_time_utc desc"""
        self.c.execute(sql)
        sql = """create view if not exists vw_summary_powershell_script_blocks
                as
                select 
                    substr(script_start, 0, 11) as script_start,
                    computer,
                    event_id,
                    event_summary,
                    count(*)
                from vw_powershell_script_blocks
                group by 1,2,3,4
                order by 1 desc"""
        self.c.execute(sql)

    def create_indexes(self):
        sql = """create index if not exists wrdl_idx_event_id on windows_received_rdp_logon(event_id);
                create index if not exists wrdl_idx_event_time_utc on windows_received_rdp_logon(event_time_utc);
                create index if not exists wrdl_idx_event_summary on windows_received_rdp_logon(event_summary);
                create index if not exists wrdl_idx_computer on windows_received_rdp_logon(computer);
                create index if not exists wrdl_idx_process_id on windows_received_rdp_logon(process_id);
                create index if not exists wrdl_idx_param1_user on windows_received_rdp_logon(param1_user);
                create index if not exists wrdl_idx_param2_domain on windows_received_rdp_logon(param2_domain);
                create index if not exists wrdl_idx_param3_IP_addr on windows_received_rdp_logon(param3_IP_addr);"""
        for sql_item in sql.replace("\n", "").split(";"):
            self.c.execute(sql_item)
        sql = """create index if not exists wl_idx_event_id on windows_logon(event_id);
                create index if not exists wl_idx_event_time_utc on windows_logon(event_time_utc);
                create index if not exists wl_idx_event_summary on windows_logon(event_summary);
                create index if not exists wl_idx_computer on windows_logon(computer);
                create index if not exists wl_idx_process_id on windows_logon(process_id);
                create index if not exists wl_idx_thread_id on windows_logon(thread_id);
                create index if not exists wl_idx_s_user_id on windows_logon(s_user_id);
                create index if not exists wl_idx_s_user_name on windows_logon(s_user_name);
                create index if not exists wl_idx_s_domain_name on windows_logon(s_domain_name);
                create index if not exists wl_idx_s_logon_id on windows_logon(s_logon_id);
                create index if not exists wl_idx_target_user_sid on windows_logon(target_user_sid);
                create index if not exists wl_idx_target_user_name on windows_logon(target_user_name);
                create index if not exists wl_idx_target_domain_name on windows_logon(target_domain_name);
                create index if not exists wl_idx_target_logon_id on windows_logon(target_logon_id);
                create index if not exists wl_idx_logon_type on windows_logon(logon_type);
                create index if not exists wl_idx_logon_process_name on windows_logon(logon_process_name);
                create index if not exists wl_idx_auth_pkg_name on windows_logon(auth_pkg_name);
                create index if not exists wl_idx_workstation_name on windows_logon(workstation_name);
                create index if not exists wl_idx_logon_guid on windows_logon(logon_guid);
                create index if not exists wl_idx_transmitted_services on windows_logon(transmitted_services);
                create index if not exists wl_idx_lm_package_name on windows_logon(lm_package_name);
                create index if not exists wl_idx_key_length on windows_logon(key_length);
                create index if not exists wl_idx_data_process_id on windows_logon(data_process_id);
                create index if not exists wl_idx_data_process_name on windows_logon(data_process_name);
                create index if not exists wl_idx_ip_addr on windows_logon(ip_addr);
                create index if not exists wl_idx_ip_port on windows_logon(ip_port);
                create index if not exists wl_idx_impersonation_level on windows_logon(impersonation_level);
                create index if not exists wl_idx_restricted_admin_mode on windows_logon(restricted_admin_mode);
                create index if not exists wl_idx_target_outbound_username on windows_logon(target_outbound_username);
                create index if not exists wl_idx_target_outbound_domain on windows_logon(target_outbound_domain);
                create index if not exists wl_idx_virtual_account on windows_logon(virtual_account);
                create index if not exists wl_idx_target_linked_logon on windows_logon(target_linked_logon);
                create index if not exists wl_idx_elevated_token on windows_logon(elevated_token);
                create index if not exists wl_idx_process_info on windows_logon(process_info);"""
        for sql_item in sql.replace("\n", "").split(";"):
            self.c.execute(sql_item)
        sql = """create index if not exists wrtuc_idx_event_id on windows_received_tcp_udp_connections(event_id);
                create index if not exists wrtuc_idx_event_time_utc on windows_received_tcp_udp_connections(event_time_utc);
                create index if not exists wrtuc_idx_event_summary on windows_received_tcp_udp_connections(event_summary);
                create index if not exists wrtuc_idx_computer on windows_received_tcp_udp_connections(computer);
                create index if not exists wrtuc_idx_process_id on windows_received_tcp_udp_connections(process_id);
                create index if not exists wrtuc_idx_thread_id on windows_received_tcp_udp_connections(thread_id);
                create index if not exists wrtuc_idx_conn_type on windows_received_tcp_udp_connections(conn_type);
                create index if not exists wrtuc_idx_client_ip on windows_received_tcp_udp_connections(thread_id);"""
        for sql_item in sql.replace("\n", "").split(";"):
            self.c.execute(sql_item)
        sql = """create index if not exists rrllgi_idx_event_id on received_rdp_logon_logoff_and_gui_info(event_id);
                create index if not exists rrllgi_idx_event_time_utc on received_rdp_logon_logoff_and_gui_info(event_time_utc);
                create index if not exists rrllgi_idx_event_summary on received_rdp_logon_logoff_and_gui_info(event_summary);
                create index if not exists rrllgi_idx_computer on received_rdp_logon_logoff_and_gui_info(computer);
                create index if not exists rrllgi_idx_process_id on received_rdp_logon_logoff_and_gui_info(process_id);
                create index if not exists rrllgi_idx_thread_id on received_rdp_logon_logoff_and_gui_info(thread_id);
                create index if not exists rrllgi_idx_provider on received_rdp_logon_logoff_and_gui_info(provider);
                create index if not exists rrllgi_channel on received_rdp_logon_logoff_and_gui_info(channel);
                create index if not exists rrllgi_security_user_id on received_rdp_logon_logoff_and_gui_info(security_user_id);
                create index if not exists rrllgi_event_data_0 on received_rdp_logon_logoff_and_gui_info(event_data_0);
                create index if not exists rrllgi_event_data_1 on received_rdp_logon_logoff_and_gui_info(event_data_1);
                create index if not exists rrllgi_event_data_2 on received_rdp_logon_logoff_and_gui_info(event_data_2);
                create index if not exists rrllgi_event_data_3 on received_rdp_logon_logoff_and_gui_info(event_data_3);
                create index if not exists rrllgi_param1_user on received_rdp_logon_logoff_and_gui_info(param1_user);
                create index if not exists rrllgi_param2_session_id on received_rdp_logon_logoff_and_gui_info(param2_session_id);
                create index if not exists rrllgi_param3_address on received_rdp_logon_logoff_and_gui_info(param3_address);
                create index if not exists rrllgi_param4_session on received_rdp_logon_logoff_and_gui_info(param4_session);
                create index if not exists rrllgi_param5_reason on received_rdp_logon_logoff_and_gui_info(param5_reason);
                create index if not exists rrllgi_param5_reason_str on received_rdp_logon_logoff_and_gui_info(param5_reason_str);"""
        for sql_item in sql.replace("\n", "").split(";"):
            self.c.execute(sql_item)
        sql = """create index if not exists mro_idx_event_id on made_rdp_outgoing(event_id);
                create index if not exists mro_idx_event_time_utc on made_rdp_outgoing(event_time_utc);
                create index if not exists mro_idx_event_summary on made_rdp_outgoing(event_summary);
                create index if not exists mro_idx_computer on made_rdp_outgoing(computer);
                create index if not exists mro_idx_process_id on made_rdp_outgoing(process_id);
                create index if not exists mro_idx_thread_id on made_rdp_outgoing(thread_id);
                create index if not exists mro_idx_provider on made_rdp_outgoing(provider);
                create index if not exists mro_channel on made_rdp_outgoing(channel);
                create index if not exists mro_security_user_id on made_rdp_outgoing(security_user_id);
                create index if not exists mro_event_data_0 on made_rdp_outgoing(event_data_0);
                create index if not exists mro_event_data_1 on made_rdp_outgoing(event_data_1);
                create index if not exists mro_event_data_2 on made_rdp_outgoing(event_data_2);
                create index if not exists mro_event_data_3 on made_rdp_outgoing(event_data_3);
                create index if not exists mro_event_data_4 on made_rdp_outgoing(event_data_4);
                create index if not exists mro_event_data_5 on made_rdp_outgoing(event_data_5);"""
        for sql_item in sql.replace("\n", "").split(";"):
            self.c.execute(sql_item)
        sql = """create index if not exists kee_idx_event_id on kaspersky_endpoint_events(event_id);
                create index if not exists kee_idx_event_time_utc on kaspersky_endpoint_events(event_time_utc);
                create index if not exists kee_idx_event_summary on kaspersky_endpoint_events(event_summary);
                create index if not exists kee_idx_computer on kaspersky_endpoint_events(computer);
                create index if not exists kee_idx_provider on kaspersky_endpoint_events(provider);
                create index if not exists kee_channel on kaspersky_endpoint_events(channel);
                create index if not exists kee_security_user_id on kaspersky_endpoint_events(security_user_id);
                create index if not exists kee_event_data_0 on kaspersky_endpoint_events(event_data_0);
                create index if not exists kee_event_data_1 on kaspersky_endpoint_events(event_data_1);
                create index if not exists kee_event_data_2 on kaspersky_endpoint_events(event_data_2);
                create index if not exists kee_event_data_3 on kaspersky_endpoint_events(event_data_3);
                create index if not exists kee_threat_param_0 on kaspersky_endpoint_events(threat_param_0);
                create index if not exists kee_threat_param_1 on kaspersky_endpoint_events(threat_param_1);
                create index if not exists kee_threat_param_2 on kaspersky_endpoint_events(threat_param_2);
                create index if not exists kee_threat_param_3 on kaspersky_endpoint_events(threat_param_3);
                create index if not exists kee_threat_param_4 on kaspersky_endpoint_events(threat_param_4);
                create index if not exists kee_threat_param_5 on kaspersky_endpoint_events(threat_param_5);
                create index if not exists kee_threat_param_6 on kaspersky_endpoint_events(threat_param_6);
                create index if not exists kee_threat_param_7 on kaspersky_endpoint_events(threat_param_7);
                create index if not exists kee_threat_param_8 on kaspersky_endpoint_events(threat_param_8);
                create index if not exists kee_threat_param_9 on kaspersky_endpoint_events(threat_param_9);
                create index if not exists kee_threat_param_10 on kaspersky_endpoint_events(threat_param_10);
                create index if not exists kee_threat_param_11 on kaspersky_endpoint_events(threat_param_11);
                create index if not exists kee_threat_param_12 on kaspersky_endpoint_events(threat_param_12);
                create index if not exists kee_threat_param_13 on kaspersky_endpoint_events(threat_param_13);
                create index if not exists kee_threat_param_14 on kaspersky_endpoint_events(threat_param_14);
                create index if not exists kee_threat_param_15 on kaspersky_endpoint_events(threat_param_15);
                create index if not exists kee_threat_param_16 on kaspersky_endpoint_events(threat_param_16);
                create index if not exists kee_threat_param_17 on kaspersky_endpoint_events(threat_param_17);
                create index if not exists kee_threat_param_18 on kaspersky_endpoint_events(threat_param_18);
                create index if not exists kee_threat_param_19 on kaspersky_endpoint_events(threat_param_19);"""
        for sql_item in sql.replace("\n", "").split(";"):
            self.c.execute(sql_item)
        sql = """create index if not exists kee_idx_event_id on symantec_endpoint_events(event_id);
                        create index if not exists kee_idx_event_time_utc on symantec_endpoint_events(event_time_utc);
                        create index if not exists kee_idx_event_summary on symantec_endpoint_events(event_summary);
                        create index if not exists kee_idx_computer on symantec_endpoint_events(computer);
                        create index if not exists kee_idx_provider on symantec_endpoint_events(provider);
                        create index if not exists kee_channel on symantec_endpoint_events(channel);
                        create index if not exists kee_security_user_id on symantec_endpoint_events(security_user_id);
                        create index if not exists kee_event_data_0 on symantec_endpoint_events(event_data_0);
                        create index if not exists kee_event_data_1 on symantec_endpoint_events(event_data_1);
                        create index if not exists kee_event_data_2 on symantec_endpoint_events(event_data_2);
                        create index if not exists kee_event_data_3 on symantec_endpoint_events(event_data_3);"""
        for sql_item in sql.replace("\n", "").split(";"):
            self.c.execute(sql_item)
        sql = """create index if not exists pssl_idx_event_id on power_shell_script_logging(event_id);
                    create index if not exists pssl_idx_event_time_utc on power_shell_script_logging(event_time_utc);
                    create index if not exists pssl_idx_event_summary on power_shell_script_logging(event_summary);
                    create index if not exists pssl_idx_computer on power_shell_script_logging(computer);
                    create index if not exists pssl_idx_process_id on power_shell_script_logging(process_id);
                    create index if not exists pssl_idx_thread_id on power_shell_script_logging(thread_id);
                    create index if not exists pssl_idx_provider on power_shell_script_logging(provider);
                    create index if not exists pssl_idxchannel on power_shell_script_logging(channel);
                    create index if not exists pssl_idxsecurity_user_id on power_shell_script_logging(security_user_id);
                    create index if not exists pssl_idxevent_data_0 on power_shell_script_logging(event_data_0);
                    create index if not exists pssl_idxevent_data_1 on power_shell_script_logging(event_data_1);
                    create index if not exists pssl_idxevent_data_2 on power_shell_script_logging(event_data_2);
                    create index if not exists pssl_idxevent_data_3 on power_shell_script_logging(event_data_3);
                    create index if not exists pssl_idxevent_data_4 on power_shell_script_logging(event_data_4);
                    create index if not exists pssl_idxevent_data_5 on power_shell_script_logging(event_data_5);
                    create index if not exists pssl_idxevent_data_6 on power_shell_script_logging(event_data_6);
                    create index if not exists pssl_idxevent_data_7 on power_shell_script_logging(event_data_7);
                    create index if not exists pssl_idxevent_data_8 on power_shell_script_logging(event_data_8);
                    create index if not exists pssl_idxevent_data_9 on power_shell_script_logging(event_data_9);
                    create index if not exists pssl_idxevent_data_10 on power_shell_script_logging(event_data_10);
                    create index if not exists pssl_idxevent_data_11 on power_shell_script_logging(event_data_11);
                    create index if not exists pssl_idxevent_data_12 on power_shell_script_logging(event_data_12);
                    create index if not exists pssl_idxevent_data_13 on power_shell_script_logging(event_data_13);
                    create index if not exists pssl_idxevent_data_14 on power_shell_script_logging(event_data_14);
                    create index if not exists pssl_idxevent_data_15 on power_shell_script_logging(event_data_15);
                    create index if not exists pssl_idxevent_data_16 on power_shell_script_logging(event_data_16);
                    create index if not exists pssl_idxevent_data_17 on power_shell_script_logging(event_data_17);
                    create index if not exists pssl_idxevent_data_18 on power_shell_script_logging(event_data_18);
                    create index if not exists pssl_idxevent_data_19 on power_shell_script_logging(event_data_19);
                    create index if not exists pssl_idx_script_block_id on power_shell_script_logging(script_block_id);
                    create index if not exists pssl_idx_script_block_text on power_shell_script_logging(script_block_text);
                    create index if not exists pssl_idx_script_msg_number on power_shell_script_logging(script_msg_number);
                    create index if not exists pssl_idx_script_msg_total on power_shell_script_logging(script_msg_total);
                    create index if not exists pssl_idx_script_path on power_shell_script_logging(script_path);
                    create index if not exists pssl_idx_script_session_id on power_shell_script_logging(script_session_id);
                    create index if not exists pssl_idx_possible_command_in_str on power_shell_script_logging(possible_command_in_str);"""
        for sql_item in sql.replace("\n", "").split(";"):
            self.c.execute(sql_item)

    def create_derived_tables(self):
        print("creating derived tables...")
        sql_find_script_blocks = """select
                                    script_start,
                                    event_id,
                                    event_summary,
                                    computer,
                                    script_block_id,
                                    script_msg_total,
                                    qtd_items
                                from vw_powershell_script_blocks
                                order by script_start desc"""
        sql_find_one = """select
                            script_block_id, 
                            script_msg_number,
                            script_block_text,
                            possible_command_in_str
                        from power_shell_script_logging
                        where script_block_id = ?
                        order by cast(script_msg_number as int) asc"""
        self.c.execute(sql_find_script_blocks)
        all_items = self.c.fetchall()
        for item in all_items:
            script_start = item[0]
            event_id = item[1]
            event_summary = item[2]
            computer = item[3]
            script_block_id = item[4]
            script_msg_total = item[5]
            self.c.execute(sql_find_one, [script_block_id])
            block_items = self.c.fetchall()
            buffer = ""
            for block_item in block_items:
                item_script_block_id = block_item[0]
                item_script_msg_number = block_item[1]
                item_script_block_text = block_item[2]
                item_possible_command_in_str = block_item[3]
                #buffer = buffer + "#Script block "+str(item_script_msg_number)+" of "+str(script_msg_total)+"\r\n"
                buffer = buffer + item_script_block_text
            buffer_hash = hashlib.md5(buffer.encode('utf-8')).hexdigest()
            insert_dict = {}
            insert_dict["event_id"] = event_id
            insert_dict["event_summary"] = event_summary
            insert_dict["script_start"] = script_start
            insert_dict["computer"] = computer
            insert_dict["script_block_id"] = script_block_id
            insert_dict["script_block_assembled"] = buffer
            insert_dict["script_hash"] = buffer_hash
            insert_dict["script_msg_total"] = script_msg_total
            self.insert_derived_powershell_script_blocks(insert_dict)


    def insert_windows_logon(self, logon_dic):
        sql = "insert into windows_logon (" \
                " event_id," \
                " event_time_utc, " \
                " event_summary, " \
                " event_record_no," \
                " computer," \
                " process_id," \
                " thread_id," \
                " s_user_id," \
                " s_user_name," \
                " s_domain_name," \
                " s_logon_id," \
                " target_user_sid," \
                " target_user_name," \
                " target_domain_name," \
                " target_logon_id," \
                " logon_type," \
                " logon_process_name," \
                " auth_pkg_name," \
                " workstation_name," \
                " logon_guid," \
                " transmitted_services," \
                " lm_package_name," \
                " key_length," \
                " data_process_id," \
                " data_process_name," \
                " ip_addr," \
                " ip_port," \
                " impersonation_level," \
                " restricted_admin_mode," \
                " target_outbound_username," \
                " target_outbound_domain," \
                " virtual_account," \
                " target_linked_logon," \
                " elevated_token )" \
              "values ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', " \
              "'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', " \
              "'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', " \
              "'%s', '%s', '%s' ) " % (
                  logon_dic["event_id"],
                  logon_dic["event_time_utc"],
                  logon_dic["event_summary"],
                  logon_dic["event_record_no"],
                  logon_dic["computer"],
                  logon_dic["process_id"],
                  logon_dic["thread_id"],
                  logon_dic["s_user_id"],
                  logon_dic["s_user_name"],
                  logon_dic["s_domain_name"],
                  logon_dic["s_logon_id"],
                  logon_dic["target_user_sid"],
                  logon_dic["target_user_name"],
                  logon_dic["target_domain_name"],
                  logon_dic["target_logon_id"],
                  logon_dic["logon_type"],
                  logon_dic["logon_process_name"],
                  logon_dic["auth_pkg_name"],
                  logon_dic["workstation_name"],
                  logon_dic["logon_guid"],
                  logon_dic["transmitted_services"],
                  logon_dic["lm_package_name"],
                  logon_dic["key_length"],
                  logon_dic["data_process_id"],
                  logon_dic["data_process_name"],
                  logon_dic["ip_addr"],
                  logon_dic["ip_port"],
                  logon_dic["impersonation_level"],
                  logon_dic["restricted_admin_mode"],
                  logon_dic["target_outbound_username"],
                  logon_dic["target_outbound_domain"],
                  logon_dic["virtual_account"],
                  logon_dic["target_linked_logon"],
                  logon_dic["elevated_token"]
              )
        self.c.execute(sql)
        self.conn.commit()

    def insert_windows_tcp_udp_connections(self, insert_dict):
        sql = "insert into windows_received_tcp_udp_connections (" \
                " event_id," \
                " event_time_utc, " \
                " event_summary, " \
                " event_record_no," \
                " computer," \
                " process_id," \
                " thread_id," \
                " conn_type," \
                " client_ip) " \
              "values ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ) "\
              " " % (
                  insert_dict["event_id"],
                  insert_dict["event_time_utc"],
                  insert_dict["event_summary"],
                  insert_dict["event_record_no"],
                  insert_dict["computer"],
                  insert_dict["process_id"],
                  insert_dict["thread_id"],
                  insert_dict["conn_type"],
                  insert_dict["client_ip"],
              )
        self.c.execute(sql)
        self.conn.commit()

    def insert_rdp_windows_logon(self, insert_dict):
        sql = "insert into windows_received_rdp_logon (" \
                " event_id," \
                " event_time_utc, " \
                " event_summary, " \
                " event_record_no," \
                " computer," \
                " process_id," \
                " thread_id," \
                " param1_user," \
                " param2_domain," \
                " param3_IP_addr) " \
              "values ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ) "\
              " " % (
                  insert_dict["event_id"],
                  insert_dict["event_time_utc"],
                  insert_dict["event_summary"],
                  insert_dict["event_record_no"],
                  insert_dict["computer"],
                  insert_dict["process_id"],
                  insert_dict["thread_id"],
                  insert_dict["param1_user"],
                  insert_dict["param2_domain"],
                  insert_dict["param3_IP_addr"],
              )
        self.c.execute(sql)
        self.conn.commit()

    def insert_received_rdp_logon_logoff_and_gui_info(self, insert_dict):
        sql = "insert into received_rdp_logon_logoff_and_gui_info (" \
                " event_id," \
                " event_time_utc, " \
                " event_summary, " \
                " event_record_no," \
                " computer," \
                " process_id," \
                " thread_id," \
                " provider," \
                " level," \
                " channel," \
                " security_user_id," \
                " event_data_0," \
                " event_data_1," \
                " event_data_2," \
                " event_data_3," \
                " param1_user," \
                " param2_session_id," \
                " param3_address," \
                " param4_session," \
                " param5_reason," \
                " param5_reason_str) " \
              "values ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', " \
              "'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ) "\
              " " % (
                  insert_dict["event_id"],
                  insert_dict["event_time_utc"],
                  insert_dict["event_summary"],
                  insert_dict["event_record_no"],
                  insert_dict["computer"],
                  insert_dict["process_id"],
                  insert_dict["thread_id"],
                  insert_dict["provider"],
                  insert_dict["level"],
                  insert_dict["channel"],
                  insert_dict["security_user_id"],
                  insert_dict["event_data_0"],
                  insert_dict["event_data_1"],
                  insert_dict["event_data_2"],
                  insert_dict["event_data_3"],
                  insert_dict["param1_user"],
                  insert_dict["param2_session_id"],
                  insert_dict["param3_address"],
                  insert_dict["param4_session"],
                  insert_dict["param5_reason"],
                  insert_dict["param5_reason_str"],
              )
        self.c.execute(sql)
        self.conn.commit()

    def insert_made_rdp_outgoing(self, insert_dict):
        sql = "insert into made_rdp_outgoing (" \
                " event_id," \
                " event_time_utc, " \
                " event_summary, " \
                " event_record_no," \
                " computer," \
                " process_id," \
                " thread_id," \
                " provider," \
                " level," \
                " channel," \
                " security_user_id," \
                " event_data_0," \
                " event_data_1," \
                " event_data_2," \
                " event_data_3," \
                " event_data_4," \
                " event_data_5) " \
              "values ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', " \
              "'%s', '%s', '%s', '%s', '%s' ) "\
              " " % (
                  insert_dict["event_id"],
                  insert_dict["event_time_utc"],
                  insert_dict["event_summary"],
                  insert_dict["event_record_no"],
                  insert_dict["computer"],
                  insert_dict["process_id"],
                  insert_dict["thread_id"],
                  insert_dict["provider"],
                  insert_dict["level"],
                  insert_dict["channel"],
                  insert_dict["security_user_id"],
                  insert_dict["event_data_0"],
                  insert_dict["event_data_1"],
                  insert_dict["event_data_2"],
                  insert_dict["event_data_3"],
                  insert_dict["event_data_4"],
                  insert_dict["event_data_5"],
              )
        self.c.execute(sql)
        self.conn.commit()

    def insert_power_shell_script_logging(self, insert_dict):
        sql = "insert into power_shell_script_logging (" \
              " event_id," \
              " event_summary, " \
              " event_time_utc, " \
              " event_record_no," \
              " computer," \
              " process_id," \
              " thread_id," \
              " provider," \
              " level," \
              " channel," \
              " security_user_id," \
              " event_data_0," \
              " event_data_1," \
              " event_data_2," \
              " event_data_3," \
              " event_data_4," \
              " event_data_5," \
              " event_data_6," \
              " event_data_7," \
              " event_data_8," \
              " event_data_9," \
              " event_data_10," \
              " event_data_11," \
              " event_data_12," \
              " event_data_13," \
              " event_data_14," \
              " event_data_15," \
              " event_data_16," \
              " event_data_17," \
              " event_data_18," \
              " event_data_19," \
              " script_block_id," \
              " script_block_text," \
              " script_msg_number," \
              " script_msg_total," \
              " script_path," \
              " script_session_id," \
              " possible_command_in_str) " \
              "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, " \
              "?, ?, ?, ?, ?, ?, ?, ? ) "
        self.c.execute(sql, list(insert_dict.values()))
        self.conn.commit()

    def insert_derived_powershell_script_blocks(self, insert_dict):
        sql = "insert into derived_powershell_script_blocks (" \
              " event_id," \
              " event_summary, " \
              " script_start, " \
              " computer," \
              " script_block_id," \
              " script_block_assembled," \
              " script_hash," \
              " script_msg_total) " \
              "values (?, ?, ?, ?, ?, ?, ?, ?)"
        self.c.execute(sql, list(insert_dict.values()))
        self.conn.commit()

    def insert_kaspersky_endpoint_events(self, insert_dict):
        sql = "insert into kaspersky_endpoint_events (" \
                " event_id," \
                " event_time_utc, " \
                " event_summary, " \
                " event_record_no," \
                " computer," \
                " provider," \
                " level," \
                " channel," \
                " security_user_id," \
                " event_data_0," \
                " event_data_1," \
                " event_data_2," \
                " event_data_3," \
                " threat_param_0," \
                " threat_param_1," \
                " threat_param_2," \
                " threat_param_3," \
                " threat_param_4," \
                " threat_param_5," \
                " threat_param_6," \
                " threat_param_7," \
                " threat_param_8," \
                " threat_param_9," \
                " threat_param_10," \
                " threat_param_11," \
                " threat_param_12," \
                " threat_param_13," \
                " threat_param_14," \
                " threat_param_15," \
                " threat_param_16," \
                " threat_param_17," \
                " threat_param_18," \
                " threat_param_19) " \
              "values ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', " \
              "'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', " \
              "'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', " \
              "'%s', '%s', '%s' ) "\
              " " % (
                  insert_dict["event_id"],
                  insert_dict["event_time_utc"],
                  insert_dict["event_summary"],
                  insert_dict["event_record_no"],
                  insert_dict["computer"],
                  insert_dict["provider"],
                  insert_dict["level"],
                  insert_dict["channel"],
                  insert_dict["security_user_id"],
                  insert_dict["event_data_0"],
                  insert_dict["event_data_1"],
                  insert_dict["event_data_2"],
                  insert_dict["event_data_3"],
                  insert_dict["threat_param_0"],
                  insert_dict["threat_param_1"],
                  insert_dict["threat_param_2"],
                  insert_dict["threat_param_3"],
                  insert_dict["threat_param_4"],
                  insert_dict["threat_param_5"],
                  insert_dict["threat_param_6"],
                  insert_dict["threat_param_7"],
                  insert_dict["threat_param_8"],
                  insert_dict["threat_param_9"],
                  insert_dict["threat_param_10"],
                  insert_dict["threat_param_11"],
                  insert_dict["threat_param_12"],
                  insert_dict["threat_param_13"],
                  insert_dict["threat_param_14"],
                  insert_dict["threat_param_15"],
                  insert_dict["threat_param_16"],
                  insert_dict["threat_param_17"],
                  insert_dict["threat_param_18"],
                  insert_dict["threat_param_19"],
              )
        self.c.execute(sql)
        self.conn.commit()

    def insert_symantec_endpoint_events(self, insert_dict):
        sql = "insert into symantec_endpoint_events (" \
                " event_id," \
                " event_time_utc, " \
                " event_summary, " \
                " event_record_no," \
                " computer," \
                " provider," \
                " level," \
                " channel," \
                " security_user_id," \
                " event_data_0," \
                " event_data_1," \
                " event_data_2," \
                " event_data_3) " \
              "values ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', " \
              "'%s', '%s', '%s' ) "\
              " " % (
                  insert_dict["event_id"],
                  insert_dict["event_time_utc"],
                  insert_dict["event_summary"],
                  insert_dict["event_record_no"],
                  insert_dict["computer"],
                  insert_dict["provider"],
                  insert_dict["level"],
                  insert_dict["channel"],
                  insert_dict["security_user_id"],
                  insert_dict["event_data_0"],
                  insert_dict["event_data_1"],
                  insert_dict["event_data_2"],
                  insert_dict["event_data_3"],
              )
        print(sql)
        print(sql)
        print(sql)
        self.c.execute(sql)
        self.conn.commit()

if __name__ == '__main__':
    db = Database()
    db.init()
    db.insert_test_record()