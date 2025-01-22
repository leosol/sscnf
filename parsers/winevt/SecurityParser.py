from parsers import GenericEvtxParser

"""
SubjectUserSid
SubjectUserName
SubjectDomainName
SubjectLogonId
TargetUserSid
TargetUserName
TargetDomainName
TargetLogonId
LogonType
LogonProcessName
AuthenticationPackageName
WorkstationName
LogonGuid
TransmittedServices
LmPackageName
KeyLength
ProcessId
ProcessName
IpAddress
IpPort
ImpersonationLevel
RestrictedAdminMode
TargetOutboundUserName
TargetOutboundDomainName
VirtualAccount
TargetLinkedLogonId
ElevatedToken
"""


class SecurityParser(GenericEvtxParser.GenericEvtxParser):
    def can_handle(self, filename):
        if "security.evtx" == filename.strip().lower():
            return True
        if "Archive-Security-2022-" in filename:
            return True
        return False

    def process(self, filepath):
        for node, err in self.xml_records(filepath):
            if err is not None:
                continue
            sys = self.get_child(node, "System")
            event_time_utc = self.parsed_date(self.get_child(sys, "TimeCreated").get("SystemTime"))
            if not self.is_event_in_selected_range(event_time_utc):
                continue
            event_id = int(self.get_child(sys, "EventID").text)
            if not (4624 == event_id or 4647 == event_id or 4648 == event_id or 4625 == event_id or 4634 == event_id
                    # active directory events
                    or 4768 == event_id or 4769 == event_id or 4776 == event_id):
                continue
            event_record_no = int(self.get_child(sys, "EventRecordID").text)
            computer = str(self.get_child(sys, "Computer").text)
            execution = self.get_child(sys, "Execution")
            process_id = execution.get("ProcessID")
            thread_id = execution.get("ThreadID")
            event_data = self.get_child(node, "EventData")
            data_dict = {}
            if event_data is not None:
                for data_item in event_data.getchildren():
                    data_name = data_item.get("Name")
                    data_dict[data_name] = data_item.text
            event_summary = {}
            event_summary[4624] = "Successful logon"
            event_summary[4647] = "Logoff initiated"
            event_summary[4648] = "A logon was attempted using explicit credentials"
            event_summary[4625] = "An account failed to log on"
            event_summary[4634] = "User is actually logged off"
            event_summary[4768] = "A Kerberos authentication ticket (TGT) was requested"
            event_summary[4769] = "A Kerberos service ticket was requested"
            event_summary[4776] = "The computer attempted to validate the credentials for an account."

            if 4624 == event_id or 4647 == event_id or 4648 == event_id or 4625 == event_id or 4634 == event_id or 4768 == event_id or 4769 == event_id or 4776 == event_id:
                insert_dict = {}
                insert_dict["event_id"] = event_id
                insert_dict["event_summary"] = event_summary[event_id]
                insert_dict["event_time_utc"] = event_time_utc
                insert_dict["event_record_no"] = event_record_no
                insert_dict["computer"] = computer
                insert_dict["process_id"] = process_id
                insert_dict["thread_id"] = thread_id
                insert_dict["s_user_id"] = data_dict.get("SubjectUserSid", "")
                insert_dict["s_user_name"] = data_dict.get("SubjectUserName", "")
                insert_dict["s_domain_name"] = data_dict.get("SubjectDomainName", "")
                insert_dict["s_logon_id"] = data_dict.get("SubjectLogonId", "")
                insert_dict["target_user_sid"] = data_dict.get("TargetUserSid", "")
                insert_dict["target_user_name"] = data_dict.get("TargetUserName", "")
                insert_dict["target_domain_name"] = data_dict.get("TargetDomainName", "")
                insert_dict["target_logon_id"] = data_dict.get("TargetLogonId", "")
                insert_dict["logon_type"] = data_dict.get("LogonType", "")
                insert_dict["logon_process_name"] = data_dict.get("LogonProcessName", "")
                insert_dict["auth_pkg_name"] = data_dict.get("AuthenticationPackageName", "")
                insert_dict["workstation_name"] = data_dict.get("WorkstationName", data_dict.get("Workstation", ""))
                insert_dict["logon_guid"] = data_dict.get("LogonGuid", "")
                insert_dict["transmitted_services"] = data_dict.get("TransmittedServices", "")
                insert_dict["lm_package_name"] = data_dict.get("LmPackageName", "")
                insert_dict["key_length"] = data_dict.get("KeyLength", "")
                insert_dict["data_process_id"] = data_dict.get("ProcessId", "")
                insert_dict["data_process_name"] = data_dict.get("ProcessName", "")
                insert_dict["ip_addr"] = data_dict.get("IpAddress", "")
                insert_dict["ip_port"] = data_dict.get("IpPort", "")
                insert_dict["impersonation_level"] = data_dict.get("ImpersonationLevel", "")
                insert_dict["restricted_admin_mode"] = data_dict.get("RestrictedAdminMode", "")
                insert_dict["target_outbound_username"] = data_dict.get("RestrictedAdminMode", "")
                insert_dict["target_outbound_domain"] = data_dict.get("TargetOutboundDomainName", "")
                insert_dict["virtual_account"] = data_dict.get("VirtualAccount", "")
                insert_dict["target_linked_logon"] = data_dict.get("TargetLinkedLogonId", "")
                insert_dict["elevated_token"] = data_dict.get("ElevatedToken", "")
                insert_dict["status"] = data_dict.get("Status", "")
                insert_dict["PackageName"] = data_dict.get("PackageName", "")
                insert_dict["ServiceName"] = data_dict.get("ServiceName", "")
                insert_dict["ServiceSid"] = data_dict.get("ServiceSid", "")
                insert_dict["TicketOptions"] = data_dict.get("TicketOptions", "")
                insert_dict["TicketEncryptionType"] = data_dict.get("TicketEncryptionType", "")
                insert_dict["TransmittedServices"] = data_dict.get("TransmittedServices", "")
                self.database.insert_windows_logon(insert_dict)
