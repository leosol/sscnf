from parsers import GenericCSVParser
from database.CSVDatabase import CSVDatabase
import os
import sys


class CsvToCsvCleaner(GenericCSVParser.GenericCSVParser):

    def __init__(self):
        super().__init__()
        self.delimiter = ','
        self.db = None
        self.skip_header_check = True
        self.row_position = 0
        self.input_delimiter = None
        self.output_delimiter = None
        self.requested_columns = None

    def can_handle(self, filename):
        if ".csv-to-csv" in filename.strip().lower():
            return True
        return False

    def pre_process_file(self, filepath):
        if self.input_delimiter is None:
            print("CSV-to-CSV: Enter input delimiter")
            if True:
                for line in sys.stdin:
                    self.input_delimiter = line.rstrip()
                    break
            print("CSV-to-CSV: Enter output delimiter")
            if True:
                for line in sys.stdin:
                    self.output_delimiter = line.rstrip()
                    break
        basename = os.path.basename(filepath)
        file_name = basename
        self.db = CSVDatabase()
        self.db.delimiter = self.output_delimiter
        self.delimiter = self.input_delimiter
        self.db.init(file_name+".csv-cleaned", self.output_dir)
        self.row_position = 0


    def finish_file(self, filepath):
        print("closing")
        #self.db.close()

    def process_row(self, row):
        if self.row_position == 0:
            col_pos = 0
            for column in row:
                print("["+str(col_pos)+"]"+column)
                col_pos = col_pos + 1
            print("Enter the columns that you need (comma separated)")
            if True:
                for line in sys.stdin:
                    self.requested_columns = line.rstrip().split(',')
                    break
            selected_row = []
            for selected_column in self.requested_columns:
                tmp = row[int(selected_column)]
                selected_row.append(tmp)
            self.db.create_csv(selected_row)
        else:
            selected_row = []
            for selected_column in self.requested_columns:
                tmp = row[int(selected_column)]
                selected_row.append(tmp.replace(" ", ","))
            self.db.csv_write_record(selected_row)
        self.row_position = self.row_position + 1
