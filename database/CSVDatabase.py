import csv


class CSVDatabase:
    def __init__(self):
        self.csv_name = None
        self.csv_file = None
        self.csv_writer = None
        self.out_dir = "."

    def init(self, csv_name, out_dir):
        if csv_name is None:
            self.csv_name = 'csv-database.csv'
        else:
            self.csv_name = csv_name
        if out_dir is None:
            self.out_dir = "."
        else:
            self.out_dir = out_dir


    def close(self):
        self.csv_writer.close()
        self.csv_file.close()

    def create_csv(self, first_line):
        self.csv_file = open(self.out_dir+"\\"+self.csv_name, mode='w', newline='', encoding='utf-8')
        self.csv_writer = csv.writer(self.csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        self.csv_writer.writerow(first_line)

    def csv_write_record(self, record):
        self.csv_writer.writerow(record)

