from parsers import GenericCSVParser
from database.DatabaseHelper import DatabaseHelper
import os


class LineByLineCSVToSQLiteParser(GenericCSVParser.GenericCSVParser):

    def __init__(self):
        super().__init__()
        self.do_only_header_check = False
        self.skip_header_check = True
        self.skip_body = False
        self.pre_process_rows = False
        self.delimiter = ';'
        self.db = None

    def can_handle(self, filename):
        if ".csv-to-db" in filename.strip().lower():
            return True
        return False

    def finish_file(self, filepath):
        self.db = None

    def process_row(self, row):
        if self.db is None:
            self.column_names = {}
            pos = 0
            for row_item in row:
                self.column_names[pos] = row_item
                pos = pos + 1
            self.db = DatabaseHelper()
            basename = os.path.basename(self.filepath)
            table_name = os.path.splitext(basename)[0]
            self.table_name = table_name.replace('-', '_')
            self.dbname = self.table_name + '.db'
            self.db.init(self.dbname, self.output_dir)
            self.db.create_database()
            self.db.create_table(self.table_name, self.column_names)
        self.db.create_record(self.table_name, self.column_names.values(), row)