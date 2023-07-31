from parsers import GenericEvtxParser


class SymantecEndpointProtectionParser(GenericEvtxParser.GenericEvtxParser):
    def can_handle(self, filename):
        if "symantec endpoint protection" in filename.strip().lower():
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
            event_record_no = int(self.get_child(sys, "EventRecordID").text)
            computer = str(self.get_child(sys, "Computer").text)
            provider = self.get_child(sys, "Provider").get("Name")
            level = self.get_child(sys, "Level").text
            channel = self.get_child(sys, "Channel").text
            security_user_id = self.get_child(sys, "Security").get("UserID")
            event_data = self.get_child(node, "EventData")
            data_dict = {}
            if event_data is not None:
                pos = 0
                for data_item in event_data.getchildren():
                    data_dict["event_data_"+str(pos)] = data_item.text
                    pos = pos+1
            event_summary = {}
            event_summary[event_id] = "Not identified - "+str(event_id)
            event_summary[2] = "verification_completed"
            event_summary[3] = "verification_start"
            event_summary[6] = "verification_err"
            event_summary[7] = "definitions"
            event_summary[12] = "config_change"
            event_summary[13] = "not_protected"
            event_summary[129] = "erro de rede"

            threat_param_dict = {}
            insert_dict = {}
            insert_dict["event_id"] = event_id
            insert_dict["event_summary"] = event_summary[event_id]
            insert_dict["event_time_utc"] = event_time_utc
            insert_dict["event_record_no"] = event_record_no
            insert_dict["computer"] = computer
            insert_dict["provider"] = provider
            insert_dict["level"] = level
            insert_dict["channel"] = channel
            insert_dict["security_user_id"] = security_user_id
            str_data_tmp = data_dict.get("event_data_0", "").replace("<string>", "").replace("</string>", "")
            str_data_tmp_items = str_data_tmp.split("\n")
            str_final_data = ""
            for item in str_data_tmp_items:
                str_final_data = str_final_data + item + "; "
            insert_dict["event_data_0"] = str_final_data.replace("'", "").replace('"', "")
            insert_dict["event_data_1"] = data_dict.get("event_data_1", "")
            insert_dict["event_data_2"] = data_dict.get("event_data_2", "")
            insert_dict["event_data_3"] = data_dict.get("event_data_3", "")
            self.database.insert_symantec_endpoint_events(insert_dict)

