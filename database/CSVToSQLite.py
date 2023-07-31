from pathlib import Path
import subprocess
import os
import sqlite3
import re


class CSVToSQLite:
    def __init__(self):
        self.csv_file = None
        self.db_file = None
        self.column_names = []
        self.csv_separator = None

    def init(self, csv_file, db_file, csv_separator=';'):
        if csv_file is None:
            self.csv_file = './csv-database.csv'
        else:
            self.csv_file = csv_file
        if db_file is None:
            self.db_file = "./csv-database.db"
        else:
            self.db_file = db_file
        self.csv_separator = csv_separator

    def create_table(self, csv_file, db_file, table_name):
        first_line = ""
        with open(csv_file) as f:
            first_line = f.readline()
        con = sqlite3.connect(db_file)
        cur = con.cursor()
        tokens = re.split('[,;]', first_line)
        tokens = [re.sub(r'[ #/()-]', '_', token) for token in tokens]
        result = []
        unknown_count = 1
        for item in tokens:
            if len(item) == 0:
                result.append(f"unknown_{unknown_count}")
                unknown_count += 1
            else:
                result.append(item)

        output_string = ','.join(result)
        sql = "CREATE TABLE IF NOT EXISTS "+table_name+" ("+output_string+")"
        print(sql)
        cur.execute(sql)
        self.column_names = output_string.split(',')
        con.commit()
        con.close()

    def create_indexes(self, db_file, table_name):
        con = sqlite3.connect(db_file)
        cur = con.cursor()
        for column_name in self.column_names:
            str_idx_creation = "create index if not exists idx_"+column_name+" on "+table_name+"("+column_name+")"
            con.execute(str_idx_creation)
        con.commit()
        con.close()

    def import_csv_to_sqlite(self, csv_file, db_file_path, table_name, separator=',', skip_first_line=True):
        skip_option = '.mode csv\n' if skip_first_line else ''
        #sqlite3 -separator "," out\csv_to_db_DATA_Filtering_by_Users.db ".import in\\DATA_Filtering_by_Users.csv-to-raw-db DATA_Filtering_by_Users"
        csv_file_path = str(csv_file).replace('\\', '\\\\')
        command = f'sqlite3 -separator "{separator}" "{db_file_path}" "{skip_option}.import \'{csv_file_path}\' {table_name}"'
        print(command)
        result = subprocess.run(command, shell=True)
        print("SubProcess result: " + str(result))

    def run_subprocess(self, db_name, csv_file, table_name):
        result = subprocess.run(['sqlite3',
                                 str(db_name),
                                 '-cmd',
                                 '.mode csv .separator '+self.csv_separator,
                                 '.import ' + str(csv_file).replace('\\', '\\\\')
                                 + " "+table_name],
                                capture_output=True)
        print("SubProcess result: "+str(result))

    def create_db(self):
        db_name = Path(self.db_file).resolve()
        csv_file = Path(self.csv_file).resolve()
        preconditions = True
        if os.path.isfile(db_name):
            print("Database file exists " + str(db_name))
            print("Trying to append data")
            preconditions = True
        if preconditions and not os.path.isfile(csv_file):
            print("CSV file does not exists " + str(csv_file))
            print("There must exist a source for the data to be converted to sqlite")
            preconditions = False
        if preconditions:
            print("Creating database " + str(db_name) + " with data from " + str(csv_file))
            basename = os.path.basename(csv_file)
            basename = os.path.splitext(basename)[0]
            table_name = basename.replace(' ', '_').replace('.', '_')
            self.create_table(csv_file, self.db_file, table_name)
            print("Calling subprocess sqlite3 - did you install it?")
            self.import_csv_to_sqlite(csv_file, db_name, table_name, self.csv_separator, False)
            #self.run_subprocess(db_name, csv_file, table_name)
            self.create_indexes(self.db_file, table_name)


if __name__ == '__main__':
    print('running csv to db')
    csv_file = 'D:\\LGMotorola_consolidado.csv'
    db_file = 'D:\\LGMotorola_consolidado.db'
    converter = CSVToSQLite()
    converter.init(csv_file, db_file)
    converter.create_db()


