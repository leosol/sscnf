from pathlib import Path
import subprocess
import os
import sqlite3


class CSVToSQLite:
    def __init__(self):
        self.csv_file = None
        self.db_file = None
        self.column_names = []

    def init(self, csv_file, db_file):
        if csv_file is None:
            self.csv_file = './csv-database.csv'
        else:
            self.csv_file = csv_file
        if db_file is None:
            self.db_file = "./csv-database.db"
        else:
            self.db_file = db_file

    def create_table(self, csv_file, db_file, table_name):
        first_line = ""
        with open(csv_file) as f:
            first_line = f.readline()
        con = sqlite3.connect(db_file)
        cur = con.cursor()
        first_line = first_line.replace(';',',')
        sql = "CREATE TABLE IF NOT EXISTS "+table_name+" ("+first_line+")"
        print(sql)
        cur.execute(sql)
        self.column_names = first_line.split(',')
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

    def run_subprocess(self, db_name, csv_file, table_name):
        result = subprocess.run(['sqlite3',
                                 str(db_name),
                                 '-cmd',
                                 '.mode csv .separator ;',
                                 '.import --skip 1 ' + str(csv_file).replace('\\', '\\\\')
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
            self.run_subprocess(db_name, csv_file, table_name)
            self.create_indexes(self.db_file, table_name)


if __name__ == '__main__':
    print('running csv to db')
    #csv_file = 'E:\\davi_locations.csv'
    #db_file = 'E:\\davi_locations.db'
    #csv_file = 'D:\\Usuarios\\root\\git\\sscnf\\input\\vt-to-database\\vt_perms_summary.csv'
    csv_file = 'D:\\Usuarios\\root\\git\\sscnf\\input\\vt-to-database\\vt_summary.csv'
    #db_file =  'D:\\Usuarios\\root\\git\\sscnf\\input\\vt-to-database\\vt_perms_summary.db'
    db_file = 'D:\\Usuarios\\root\\git\\sscnf\\input\\vt-to-database\\vt_summary.db'
    converter = CSVToSQLite()
    converter.init(csv_file, db_file)
    converter.create_db()


