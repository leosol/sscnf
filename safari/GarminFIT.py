import fitparse
import traceback
import requests
import sys
import time
from parsers import GenericParser
from database.DatabaseHelper import DatabaseHelper
from database.CSVDatabase import CSVDatabase
import os

class GarminFIT(GenericParser.GenericParser):
    def __init__(self, dbname, dbpath):
        print("GarminFIT: __init__")
        self.db = DatabaseHelper()
        self.db.init(dbname, dbpath)
        self.db.create_database()
        self.table_name = "locations"
        self.column_names = ["file_path", "file_dir", "reg_timestamp", "reg_lat", "reg_long"]
        self.db.create_table(self.table_name, self.column_names)
        self.alternative_out_csv = CSVDatabase()
        self.alternative_out_csv.init("garmin-locations.csv", dbpath)
        self.alternative_out_csv.create_csv(self.column_names)
        self.backend_only_csv = True


    def can_handle(self, filename):
        if filename.strip().lower().endswith('.fit'):
            return True
        return False

    def process(self, filepath):
        fitfile = fitparse.FitFile(filepath)
        folder_path = os.path.dirname(filepath)
        for record in fitfile.get_messages('record'):
            latitude = ""
            longitude = ""
            date = ""
            has_record = False
            for record_data in record:
                if record_data.name == 'position_lat':
                    latitude = record_data.value * (180.0 / 2**31)
                    if len(str(latitude)) > 1 :
                        has_record = True
                elif record_data.name == 'position_long':
                    longitude = record_data.value * (180.0 / 2**31)
                    if len(str(longitude))> 1:
                        has_record = True
                elif record_data.name == 'timestamp':
                    date = record_data.value
                else:
                    self.write_log_msg("GarminFit - Missing Name "+record_data.name)
            if has_record:
                values = [filepath, folder_path, date, latitude, longitude]
                if self.backend_only_csv:
                    self.alternative_out_csv.csv_write_named_values(self.column_names, values)
                else:
                    self.db.create_record(self.table_name, self.column_names, values)
