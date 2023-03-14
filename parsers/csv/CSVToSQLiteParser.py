from parsers import GenericParser
import os
from database.CSVToSQLite import CSVToSQLite


class CSVToSQLiteParser(GenericParser.GenericParser):

    def can_handle(self, filename):
        if ".csv" in filename.strip().lower():
            return True
        return False

    def process(self, filepath):
        if not("csvtosqlite" in filepath.strip().lower()):
            return
        csv_file = filepath
        basename = os.path.basename(csv_file)
        basename_noext = os.path.splitext(basename)[0]
        sqlite_db = self.output_dir+"csv_to_db_"+basename_noext+".db"
        db_file = sqlite_db
        converter = CSVToSQLite()
        converter.init(csv_file, db_file)
        converter.create_db()