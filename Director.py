import os
from parsers.winevt.TSLocalSessionManagerParser import TSLocalSessionManagerParser
from parsers.winevt.TSRemoteConnectionManagerParser import TSRemoteConnectionManagerParser
from parsers.winevt.SecurityParser import SecurityParser
from parsers.winevt.RDPCoreTS import RDPCoreTS
from parsers.winevt.TSRDPClientParser import TSRDPClientParser
from parsers.winevt.KasperskyEndpointParser import KasperskyEndpointParser
from parsers.winevt.PowerShellParser import PowerShellParser
from parsers.csv.IPEDBRFileListing import IPEDBRFileListing
from parsers.csv.CSVToSQLiteParser import CSVToSQLiteParser
from parsers.fortianalyzer.FortiAnalyzerToDatabase import FortiAnalyzerToDatabase
from parsers.csv.LineByLineCSVToSQLiteParser import LineByLineCSVToSQLiteParser
from enrichers.WiFi.BssidEnricher import BssidEnricher
from database.Database import Database
from database.CSVDatabase import CSVDatabase
from enrichers.virustotal.VTUploader import  VTUploader
from parsers.phones.iTunesBackupOldParser import  iTunesBackupOldParser
from datetime import datetime
from parsers.apk.JadxDecode import JadxDecode
from parsers.apk.ApkToolDecode import ApkToolDecode
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

    def configure_phone_parsers(self):
        iTunesOldParser = iTunesBackupOldParser()
        iTunesOldParser.set_dest_dir(self.out_dir )
        iTunesOldParser.set_manifest_db(self.rootdir + "\\Manifest.db")
        self.parsers.append(iTunesOldParser)

    def configure_parsers(self):
        self.configure_winevt_parsers()
        self.configure_csv_parsers()
        self.configure_extra_parsers()
        self.configure_enrichers()
        for parser in self.parsers:
            parser.configure_db(self.database)
            parser.configure_output(self.out_dir)
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
        ipedBR.configure_range("2022-10-01 23:59:59", "2023-03-01 23:59:59")
        fortianalyzer = FortiAnalyzerToDatabase()
        fortianalyzer.init('fortianalyzer.db', self.out_dir)
        lineByLineCSVToSQLiteParser = LineByLineCSVToSQLiteParser()
        self.range_start = None
        self.range_end = None
        #self.parsers.append(ipedBR)
        self.parsers.append(fortianalyzer)
        #self.parsers.append(lineByLineCSVToSQLiteParser)


    def configure_winevt_parsers(self):
        self.parsers.append(TSRemoteConnectionManagerParser())
        self.parsers.append(SecurityParser())
        self.parsers.append(TSLocalSessionManagerParser())
        self.parsers.append(RDPCoreTS())
        self.parsers.append(TSRDPClientParser())
        self.parsers.append(KasperskyEndpointParser())
        self.parsers.append(PowerShellParser())

    def configure_extra_parsers(self):
        #self.parsers.append(ApkToolDecode())
        #self.parsers.append(JadxDecode())
        self.parsers.append(CSVToSQLiteParser())

    def configure_enrichers(self):
        self.parsers.append(BssidEnricher())
        self.parsers.append(VTUploader(self.out_dir))

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
    input = '.\\input\\'
    output = '.\\output\\'
    print("Enter input dir:")
    if True:
        for line in sys.stdin:
            input = line.rstrip()
            break
    print("Enter output dir:")
    if True:
        for line in sys.stdin:
            output = line.rstrip()
            break
    main_db = output + 'main.db'
    db = Database()
    db.init(main_db)
    d = Director(input, db, output)
    #d.configure_phone_parsers()
    d.configure_parsers()
    d.process()
    db.create_indexes()
    db.create_derived_tables()
