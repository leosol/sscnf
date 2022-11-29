from parsers import GenericParser
import csv
from datetime import datetime
import pytz
import traceback
import sys


class GenericCSVParser(GenericParser.GenericParser):

    def __init__(self):
        super().__init__()
        self.line_count = 0
        self.do_only_header_check = False

    def check_header_only(self, do_only_header_check):
        self.do_only_header_check = do_only_header_check

    def array_equal(self, a, b):
        if len(a) != len(b):
            return False
        arr_size = len(a)
        for i in range(arr_size):
            if a[i] != b[i]:
                return False
        return True

    def parse_datetime(self, strdtime):
        ts = strdtime
        try:
            if len(strdtime) > 10:
                strdtime = strdtime.replace("BRT", "-0300")
                strdtime = strdtime.replace("BRST", "-0200")
                # "Fri Aug 14 09:19:17 BRT 2020"
                tsd = datetime.strptime(strdtime, "%a %b %d %H:%M:%S %z %Y")
                ts = tsd.astimezone(pytz.UTC).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            print(sys.exc_info()[2])
            print(traceback.format_exc())
            ts = strdtime
        return ts

    def get_expected_first_line(self):
        print("This should be overriden")
        return []

    def process_row(self, row):
        print("This should be overriden")

    def process(self, filepath):
        line_count = 0
        with open(filepath, newline='', encoding='utf-8-sig') as csv_file:
            reader = csv.reader(csv_file, delimiter=';', quotechar='"')
            for row in reader:
                try:
                    if line_count == 0:
                        if self.array_equal(self.get_expected_first_line(), row):
                            print("CSV has expected structure")
                        else:
                            print("CSV does not have the expected structure")
                            return
                    else:
                        if self.do_only_header_check:
                            return
                        self.process_row(row)
                except Exception as e:
                    print(sys.exc_info()[2])
                    print(traceback.format_exc())
                line_count = line_count + 1
