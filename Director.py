import os
from parsers.winevt.TSLocalSessionManagerParser import TSLocalSessionManagerParser
from parsers.winevt.TSRemoteConnectionManagerParser import TSRemoteConnectionManagerParser
from parsers.winevt.SecurityParser import SecurityParser
from parsers.winevt.RDPCoreTS import RDPCoreTS
from parsers.winevt.TSRDPClientParser import TSRDPClientParser
from parsers.winevt.KasperskyEndpointParser import KasperskyEndpointParser
from parsers.winevt.PowerShellParser import PowerShellParser
from parsers.csv.IPEDBRFileListing import IPEDBRFileListing
from database.Database import Database
from database.CSVDatabase import CSVDatabase
from datetime import datetime
import traceback
import time
import sys

#rootdir = '.\\input-evtx\\'
#https://frsecure.com/blog/rdp-connection-event-logs/

def parsed_date(dstr):
    ts = None
    try:
        ts = datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        ts = datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S.%f')
    return ts

class Director:
    def __init__(self, rootdir, database, out_dir):
        self.parsers = []
        self.rootdir = rootdir
        self.suspected_accounts = []
        self.suspected_ips = []
        self.suspected_src = []
        self.range_start = None
        self.range_end = None
        self.database = database
        self.files_to_process = 0
        self.processed_files = 0
        self.out_dir = out_dir

    def configure_parsers(self):
        #self.configure_winevt_parsers()
        self.configure_csv_parsers()
        for parser in self.parsers:
            parser.configure_db(self.database)
            parser.suspected_accounts = self.suspected_accounts
            parser.suspected_ips = self.suspected_ips
            parser.suspected_src = self.suspected_src
            if self.range_start is not None:
                parser.range_start = parser.parsed_date(self.range_start)
            if self.range_end is not None:
                parser.range_end = parser.parsed_date(self.range_end)

    def configure_csv_parsers(self):
        ipedBR = IPEDBRFileListing()
        csv_database = CSVDatabase()
        csv_database.init("iped_br_file_listing.csv", self.out_dir)
        ipedBR.configure_csv_database(csv_database)
        ipedBR.check_header_only(False)
        ipedBR.configure_range("2022-04-01 23:59:59", "2022-09-01 23:59:59")
        self.range_start = None
        self.range_end = None
        self.parsers.append(ipedBR)


    def configure_winevt_parsers(self):
        self.parsers.append(TSRemoteConnectionManagerParser())
        self.parsers.append(SecurityParser())
        self.parsers.append(TSLocalSessionManagerParser())
        self.parsers.append(RDPCoreTS())
        self.parsers.append(TSRDPClientParser())
        self.parsers.append(KasperskyEndpointParser())
        self.parsers.append(PowerShellParser())


    def count_files(self):
        for subdir, dirs, files in os.walk(self.rootdir):
            for file in files:
                for parser in self.parsers:
                    if parser.can_handle(file):
                        to_be_processed = os.path.join(subdir, file)
                        try:
                            if os.stat(to_be_processed).st_size == 0:
                                continue
                            print("Parser can handle file : " + to_be_processed)
                            self.files_to_process = self.files_to_process+1
                        except Exception as e:
                            print(sys.exc_info()[2])
                            print(traceback.format_exc())

    def process(self):
        self.count_files()
        self.processed_files = 0
        gstart_time = time.time()
        for subdir, dirs, files in os.walk(self.rootdir):
            for file in files:
                can_handle = False
                for parser in self.parsers:
                    if parser.can_handle(file):
                        can_handle = True
                        file_to_process = os.path.join(subdir, file)
                        try:
                            if os.stat(file_to_process).st_size == 0:
                                continue
                            print("Processing file : " + file_to_process + " ---------------------------")
                            start_time = time.time()
                            parser.process(file_to_process)
                            print("Processing took %s seconds ---" % (time.time() - start_time))
                        except Exception as e:
                            print(sys.exc_info()[2])
                            print(traceback.format_exc())
                if can_handle:
                    self.processed_files = self.processed_files + 1
                    print("Processed files %d of %d took until now %s " % (self.processed_files, self.files_to_process, time.time() - gstart_time))
                    avg_time_per_file = (time.time() - gstart_time) / (self.processed_files * 1.0)
                    eta = avg_time_per_file * (self.files_to_process - self.processed_files)
                    print("ETA %s seconds or %s hours" % (eta, eta/60.0/60.0))

if __name__ == '__main__':
    db = Database()
    db.init('..\\output\\output.db')
    d = Director('..\\input\\iped-file-listing\\', db, "..\\output\\")
    d.configure_parsers()
    d.process()
    db.create_indexes()
    db.create_derived_tables()
