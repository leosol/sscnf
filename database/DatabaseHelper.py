import sqlite3
import hashlib


class DatabaseHelper:

    def init(self, dbname, dbpath):
        self.dbname = dbname
        self.dbpath = dbpath

    def create_database(self):
        self.conn = sqlite3.connect(self.dbpath + '/' + self.dbname)
        self.c = self.conn.cursor()

    def get_table_columns(self, table_name):
        try:
            exec_obj = self.conn.execute('select * from '+table_name)
            names = [description[0] for description in exec_obj.description]
            return names
        except:
            return []

    def create_table(self, table_name, columns):
        columns_spec = ''
        qtd_columns = 0
        for column in columns:
            if qtd_columns > 0:
                columns_spec = columns_spec + ', '
            columns_spec = columns_spec + column + ' TEXT'
            qtd_columns = qtd_columns + 1
        sql = 'create table if not exists ' + table_name + ' (internal_id INTEGER PRIMARY KEY,' + columns_spec + ')'
        print(sql)
        self.c.execute(sql)

    def create_record(self, table_name, columns, data):
        if len(columns) != len(data):
            raise Exception("Invalid RECORD: " + str(len(columns)) + " columns and " + str(len(data)) + ". Should be equal")
        column_spec = ''
        binding_spec = ''
        qtd_columns = 0
        for column in columns:
            if qtd_columns > 0:
                column_spec = column_spec + ', '
                binding_spec = binding_spec + ', '
            column_spec = column_spec + column
            binding_spec = binding_spec + '?'
            qtd_columns = qtd_columns + 1
        sql = 'insert into ' + table_name + '(' + column_spec + ') values (' + binding_spec + ')'
        self.c.execute(sql, data)
        self.conn.commit()

    def create_index(self, table_name, columns):
        for column in columns:
            sql = 'create index if not exists idx_' + table_name + '_' + column + '(' + column + ')'
            self.c.execute(sql)
            self.conn.commit()
