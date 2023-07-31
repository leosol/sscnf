from parsers import GenericParser
import os
import sys
from database.CSVToSQLite import CSVToSQLite


class CSVToSQLiteParser(GenericParser.GenericParser):

    def __init__(self):
        self.csv_separator = None

    def can_handle(self, filename):
        if ".csv-to-raw-db" in filename.strip().lower():
            if self.csv_separator is None:
                print("Enter csv-to-raw-db separator:")
                if True:
                    for line in sys.stdin:
                        self.csv_separator = line.rstrip()
                        break
            return True
        return False

    def process(self, filepath):
        csv_file = filepath
        basename = os.path.basename(csv_file)
        basename_noext = os.path.splitext(basename)[0]
        sqlite_db = self.output_dir+"csv_to_db_"+basename_noext+".db"
        db_file = sqlite_db
        converter = CSVToSQLite()
        converter.init(csv_file, db_file, self.csv_separator)
        converter.create_db()