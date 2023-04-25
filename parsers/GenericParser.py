from datetime import datetime

class GenericParser:
    def __init__(self):
        super().__init__()
        self.suspected_accounts = []
        self.suspected_ips = []
        self.suspected_src = []
        self.range_start = None
        self.range_end = None
        self.database = None

    def configure_output(self, output_dir):
        self.output_dir = output_dir

    def configure_range(self, range_start, range_end):
        self.range_start = self.parsed_date(range_start)
        self.range_end = self.parsed_date(range_end)

    def configure_db(self, database):
        self.database = database

    def can_handle(self, filename):
        return False

    def parsed_date(self, dstr):
        ts = None
        try:
            ts = datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            ts = datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S.%f')
        return ts

    def event_in_daterange(self, d, start, end):
        is_in_range = True
        if d < start:
            is_in_range = False
        if d > end:
            is_in_range = False
        return is_in_range

    def is_event_in_selected_range(self, evtdate):
        if self.range_start is not None and self.range_end is not None:
            return self.event_in_daterange(evtdate, self.range_start, self.range_end)
        return True

    def is_suspected_account(self, account):
        if not self.suspected_accounts:
            return True
        a = account.strip().lower()
        for item in self.suspected_accounts:
            if a == item:
                return True
        return False

    def is_suspected_ip(self, ip):
        if not self.suspected_ips:
            return True
        a = ip.strip().lower()
        for item in self.suspected_ips:
            if a == item:
                return True
        return False

    def is_suspected_src(self, src):
        if not self.suspected_src:
            return True
        a = src.strip().lower()
        for item in self.suspected_src:
            if a == item:
                return True
        return False

    def write_log_msg(self, msg):
        if self.logf is not None:
            self.logf.write(msg)
