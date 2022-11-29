from parsers import GenericEvtxParser


class TSRemoteConnectionManagerParser(GenericEvtxParser.GenericEvtxParser):

    def can_handle(self, filename):
        if "TerminalServices" in filename and "RemoteConnectionManage" in filename:
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
            if not (1149 == event_id):
                continue
            event_record_no = int(self.get_child(sys, "EventRecordID").text)
            computer = str(self.get_child(sys, "Computer").text)
            execution = self.get_child(sys, "Execution")
            process_id = execution.get("ProcessID")
            thread_id = execution.get("ThreadID")
            event_summary = {}
            event_summary[1149] = "Remote Desktop - Successful logon"
            if 1149 == event_id:
                usr_data = self.get_child(node, "UserData")
                usr_data_evt_xml = self.get_child2(usr_data, "EventXML")
                param1_user = str(self.get_child2(usr_data_evt_xml, "Param1").text)
                param2_domain = str(self.get_child2(usr_data_evt_xml, "Param2").text)
                param3_IP_addr = str(self.get_child2(usr_data_evt_xml, "Param3").text)

                insert_dict = {}
                insert_dict["event_id"] = event_id
                insert_dict["event_summary"] = event_summary[event_id]
                insert_dict["event_time_utc"] = event_time_utc
                insert_dict["event_record_no"] = event_record_no
                insert_dict["computer"] = computer
                insert_dict["process_id"] = process_id
                insert_dict["thread_id"] = thread_id
                insert_dict["param1_user"] = param1_user
                insert_dict["param2_domain"] = param2_domain
                insert_dict["param3_IP_addr"] = param3_IP_addr
                self.database.insert_rdp_windows_logon(insert_dict)


