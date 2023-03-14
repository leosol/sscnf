import sqlite3
import datetime as dt
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import pandas as pd
from datetime import datetime
import matplotlib.dates as mdates
from matplotlib.collections import PolyCollection
import numpy as np

def parse_dt(strd):
    return dt.datetime.strptime(strd, '%Y-%m-%d %H:%M:%S')

class RansomwareEncriptionChart:
    def __init__(self):
        self.ransomware_hashes = []
        self.ransomware_ext = None
        self.iped_files_db = None

    def init(self, ransomware_hashes, ransomware_ext, iped_files_db):
        self.ransomware_hashes = ransomware_hashes
        self.ransomware_ext = ransomware_ext
        self.iped_files_db = iped_files_db

    def get_data_from_db(self):
        con = sqlite3.connect(self.iped_files_db)
        cur = con.cursor()
        hashes_str = "\", \"".join(self.ransomware_hashes)
        hashes_str = hashes_str.upper()
        ext_str = self.ransomware_ext.lower()
        str_query = """select evidence, 
                        max(min(cdate), min(mdate), min(adate)) as dt_ini, 
                        min(max(cdate), max(mdate), max(adate)) as dt_end,
                        count(*)
                    from iped_br_file_listing_csv
                    where lower(name) like '%."""+ext_str+"""' or upper(hash) in (\""""+hashes_str+"""\")
                    group by evidence
                    order by 2 desc"""
        print("--------------------Query-------------------")
        print(str_query)
        print("--------------------/Query-------------------")
        cur = con.cursor()
        cur.execute(str_query)
        rows = cur.fetchall()
        con.close()
        return rows

    def get_first_and_last_event(self, data):
        min_date = None
        max_date = None
        print("########data#########")
        for item in data:
            print(item)
            if min_date is None:
                min_date = item[1]
            else:
                if min_date > item[1]:
                    min_date = item[1]
            if max_date is None:
                max_date = item[2]
            else:
                if max_date < item[2]:
                    max_date = item[2]
        print("########data#########")
        return datetime.strptime(min_date, '%Y-%m-%d %H:%M:%S'), datetime.strptime(max_date, '%Y-%m-%d %H:%M:%S')

    def get_hours_btw_dates(self, dt_end, dt_start):
        duration = dt_end - dt_start
        duration_in_hours = duration.total_seconds()/60/60
        return duration_in_hours

    def clean_column_str(self, text_to_clean):
        index_slash = text_to_clean.find('/')
        index_dot = text_to_clean.find('.')
        index_minus = text_to_clean.find('-')
        if index_dot > -1 and index_minus > -1:
            last_index = min(index_dot, index_minus)
        else:
            last_index = max(index_dot, index_minus)
        sub_str = text_to_clean[index_slash+1:last_index]
        return sub_str.upper()

    def plot_chart(self):
        data = self.get_data_from_db()
        start_dt, end_date = self.get_first_and_last_event(data)
        fig, ax = plt.subplots(1, figsize=(16, 6))
        pos_in_data = 0
        for d in data:
            str_evidence = self.clean_column_str(d[0])
            evidence_ini = datetime.strptime(d[1], '%Y-%m-%d %H:%M:%S')
            evidence_end = datetime.strptime(d[2], '%Y-%m-%d %H:%M:%S')
            hours_from_min_to_start = self.get_hours_btw_dates(evidence_ini, start_dt)
            hours_from_min_to_end = self.get_hours_btw_dates(evidence_end, start_dt)
            print(str_evidence, str(start_dt), str(evidence_ini), str(evidence_end), str(hours_from_min_to_start), str(hours_from_min_to_end))
            item = ax.barh(str_evidence, width=(hours_from_min_to_end-hours_from_min_to_start), left=hours_from_min_to_start)
        ##### TICKS #####
        total_hours = self.get_hours_btw_dates(end_date, start_dt)
        print('start/end/tota hours', str(start_dt), str(end_date), str(total_hours))
        xticks_hour_factor = 2.0/6.0
        xticks = np.arange(0, total_hours, xticks_hour_factor)
        xticks_labels = pd.date_range(start_dt, end_date, freq=str((60*xticks_hour_factor))+"min").strftime('%H:%M')
        print('ticks len', str(len(xticks)), str(len(xticks_labels)))
        ax.set_xticks(xticks, minor=True)
        ax.set_xticklabels(xticks_labels, minor=True)
        major_xticks = [0, total_hours]
        major_xticks_labels = [start_dt.strftime('%Y-%m-%d %H:%M'), end_date.strftime('%Y-%m-%d %H:%M')]
        ax.set_xticks(major_xticks)
        ax.set_xticklabels(major_xticks_labels)
        plt.xticks(rotation=90)
        plt.show()


    def plot_data_chart(self):
        data = (
                ('Task A', 'MKT', '2022-02-15', '2022-02-20', 1.0, 0, 5, 5, '#E64646'),
                ('Task B', 'MKT', '2022-02-19', '2022-02-24', 1.0, 4, 9, 5, '#E69646')
        )
        fig, ax = plt.subplots(1, figsize=(16, 6))
        for d in data:
            ax.barh(d[0], d[7], left=d[5], color=d[8])

        ##### LEGENDS #####
        c_dict = {'MKT': '#E64646', 'FIN': '#E69646', 'ENG': '#34D05C',
                  'PROD': '#34D0C3', 'IT': '#3475D0'}
        legend_elements = [Patch(facecolor=c_dict[i], label=i) for i in c_dict]
        plt.legend(handles=legend_elements)

        ##### TICKS #####
        xticks = np.arange(0, 9 + 1, 3)
        xticks_labels = pd.date_range('2022-02-01', end='2022-02-28').strftime("%m/%d")
        xticks_minor = np.arange(0, 15 + 1, 1)
        ax.set_xticks(xticks)
        ax.set_xticks(xticks_minor, minor=True)
        ax.set_xticklabels(xticks_labels[::7])

        plt.show()



if __name__ == '__main__':
    iped_files_db = '..\\input\\produced\\iped_br_file_listing.db'
    chart = RansomwareEncriptionChart()
    chart.init(["B311256C0B964724258078AFFCE39F01-asdfasdfasdf"], "play", iped_files_db)
    chart.plot_chart()
    #chart.plot_data_chart()
    val = input("Enter your value: ")
    print(val)
