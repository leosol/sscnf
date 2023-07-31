from parsers import GenericCSVParser
from database.DatabaseHelper import DatabaseHelper
from database.CSVDatabase import CSVDatabase
import os
import sys


class FortiAnalyzerToDatabase(GenericCSVParser.GenericCSVParser):

    def init(self, dbname, dbpath):
        self.db = DatabaseHelper()
        self.db.init(dbname, dbpath)
        self.skip_header_check = True
        self.pre_process_rows = True
        self.use_unique_names = True
        self.skip_body = False
        self.delimiter = ' '
        self.column_names = {}
        self.db.create_database()
        self.lost_columns = []
        self.missed_columns = []
        self.multiple_names_same_column = {}
        self.unique_column_names = []
        self.no_database = False
        self.alternative_out_csv = None
        self.disabled = True
        print("FortiAnalyzerToDatabase: enable? (enter True)")
        if True:
            for line in sys.stdin:
                helper = line.rstrip()
                if "True" in helper:
                    self.disabled = False
                break


    def can_handle(self, filename):
        if self.disabled:
            return False
        if filename.strip().lower().endswith('.csv'):
            return True
        return False

    def check_table_integrity(self):
        self.lost_columns = []
        self.missed_columns = []
        table_columns = self.db.get_table_columns(self.table_name)
        if len(table_columns) == 0:
            return False
        for to_insert_column in self.column_names.values():
            if to_insert_column not in table_columns:
                self.lost_columns.append(to_insert_column)
        for placeholder_column in table_columns:
            if placeholder_column not in self.column_names.values():
                self.missed_columns.append(placeholder_column)
        return len(self.lost_columns) > 0 or len(self.missed_columns) > 0

    def pre_process_file(self, filepath):
        basename = os.path.basename(filepath)
        table_name = os.path.splitext(basename)[0]
        table_name = os.path.splitext(table_name)[0]
        self.table_name = table_name.replace('-', '_').replace('.','_')
        super().pre_process_file(filepath)
        self.normalize_columns_without_names()
        print("Columns in the file: " + filepath)
        print(self.column_names)
        integrity_problem = self.check_table_integrity()
        if integrity_problem:
            print("Columns present in the file that will be lost: "+str(self.lost_columns))
            print("Columns not present in the database, but in the file: "+str(self.missed_columns))
        print("Multiple column names for the same column: ")
        print(self.multiple_names_same_column)
        print("Unique Column names: ")
        print(self.unique_column_names)
        self.alternative_out_csv = CSVDatabase()
        self.alternative_out_csv.init("fortianalyzer-csv", self.output_dir)
        if self.use_unique_names:
            self.db.create_table(self.table_name, self.unique_column_names)
            self.alternative_out_csv.create_csv(self.unique_column_names)
        else:
            self.db.create_table(self.table_name, self.column_names.values())
            self.alternative_out_csv.create_csv(self.column_names.values())
        self.row_num = 0



    def normalize_columns_without_names(self):
        for i in range(0, len(self.column_names)):
            if self.column_names[i] is None:
                self.column_names[i] = 'Missing_'+str(i)
        for i in range(0, len(self.column_names)):
            if self.column_names[i] is not None:
                if self.column_names[i] not in self.unique_column_names:
                    self.unique_column_names.append(self.column_names[i])
        for item in self.multiple_names_same_column:
            multiple_names_for_item = self.multiple_names_same_column[item]
            for i in range(0, len(multiple_names_for_item)):
                if multiple_names_for_item[i] not in self.unique_column_names:
                    self.unique_column_names.append(multiple_names_for_item[i])

    def pre_process_row(self, row):
        column_index = 0
        for column in row:
            if column_index in self.column_names:
                current_column_name = self.column_names.get(column_index)
            else:
                current_column_name = None
            by_row_column_name = None
            if '=' in column:
                by_row_column_name = column.split('=')[0]
            else:
                by_row_column_name = None
            if current_column_name is None or len(current_column_name) < 2:
                current_column_name = by_row_column_name
                self.column_names[column_index] = self.handle_key_words(current_column_name)
            else:
                if by_row_column_name is not None and current_column_name is not None:
                    if self.handle_key_words(by_row_column_name) != current_column_name:
                        if column_index in self.multiple_names_same_column:
                            if self.handle_key_words(by_row_column_name) not in self.multiple_names_same_column[column_index]:
                                self.multiple_names_same_column[column_index].append(self.handle_key_words(by_row_column_name))
                        else:
                            self.multiple_names_same_column[column_index] = []
                            self.multiple_names_same_column[column_index].append(self.handle_key_words(by_row_column_name))
            column_index = column_index + 1

    def handle_key_words(self, colum_name):
        if colum_name is not None:
            colum_name = colum_name.replace('-', '_').replace('.','_')
            return "clmn_"+colum_name
        return None

    def process_row(self, row):
        data_with_empty = []
        data = []
        columns = []
        for column in row:
            if '=' in column:
                value = column.split('=')[1]
                column = self.handle_key_words(column.split('=')[0])
                if column in self.unique_column_names:
                    data.append(value)
                    columns.append(column)
            else:
                value = column
            data_with_empty.append(value)
        if self.no_database:
            if self.use_unique_names:
                self.alternative_out_csv.csv_write_named_values(columns, data)
            else:
                self.db.create_record(self.table_name, self.column_names.values(), data_with_empty)
        else:
            if self.use_unique_names:
                self.db.create_record(self.table_name, columns, data)
            else:
                self.db.create_record(self.table_name, self.column_names.values(), data_with_empty)

    def process(self, filepath):
        self.column_names = {}
        self.lost_columns = []
        self.missed_columns = []
        self.multiple_names_same_column = {}
        super().process(filepath)