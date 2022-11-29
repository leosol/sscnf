from parsers import GenericEvtxParser


class KasperskyEndpointParser(GenericEvtxParser.GenericEvtxParser):
    def can_handle(self, filename):
        if "kaspersky endpoint security" in filename.strip().lower():
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
            if not(302 == event_id or 218 == event_id ):
                continue
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
            event_summary[302] = "Malicious Object Detected"
            event_summary[218] = "Configuration changed"
            threat_param_dict = {}
            if 302 == event_id:
                str_threat = data_dict.get("event_data_0", "").replace("<string>", "").replace("</string>", "")
                threat_items = str_threat.split("\n")
                pos = 0
                for item in threat_items:
                    threat_param_dict["threat_param_"+str(pos)] = item
                    pos = pos + 1
            if 302 == event_id or 218 == event_id:
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
                insert_dict["event_data_0"] = data_dict.get("event_data_0", "")
                insert_dict["event_data_1"] = data_dict.get("event_data_1", "")
                insert_dict["event_data_2"] = data_dict.get("event_data_2", "")
                insert_dict["event_data_3"] = data_dict.get("event_data_3", "")
                insert_dict["threat_param_0"] = threat_param_dict.get("threat_param_0", "")
                insert_dict["threat_param_1"] = threat_param_dict.get("threat_param_1", "")
                insert_dict["threat_param_2"] = threat_param_dict.get("threat_param_2", "")
                insert_dict["threat_param_3"] = threat_param_dict.get("threat_param_3", "")
                insert_dict["threat_param_4"] = threat_param_dict.get("threat_param_4", "")
                insert_dict["threat_param_5"] = threat_param_dict.get("threat_param_5", "")
                insert_dict["threat_param_6"] = threat_param_dict.get("threat_param_6", "")
                insert_dict["threat_param_7"] = threat_param_dict.get("threat_param_7", "")
                insert_dict["threat_param_8"] = threat_param_dict.get("threat_param_8", "")
                insert_dict["threat_param_9"] = threat_param_dict.get("threat_param_9", "")
                insert_dict["threat_param_10"] = threat_param_dict.get("threat_param_10", "")
                insert_dict["threat_param_11"] = threat_param_dict.get("threat_param_11", "")
                insert_dict["threat_param_12"] = threat_param_dict.get("threat_param_12", "")
                insert_dict["threat_param_13"] = threat_param_dict.get("threat_param_13", "")
                insert_dict["threat_param_14"] = threat_param_dict.get("threat_param_14", "")
                insert_dict["threat_param_15"] = threat_param_dict.get("threat_param_15", "")
                insert_dict["threat_param_16"] = threat_param_dict.get("threat_param_16", "")
                insert_dict["threat_param_17"] = threat_param_dict.get("threat_param_17", "")
                insert_dict["threat_param_18"] = threat_param_dict.get("threat_param_18", "")
                insert_dict["threat_param_19"] = threat_param_dict.get("threat_param_19", "")
                self.database.insert_kaspersky_endpoint_events(insert_dict)

