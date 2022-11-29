from parsers import GenericCSVParser


class IPEDBRFileListing(GenericCSVParser.GenericCSVParser):

    def __init__(self):
        super().__init__()
        self.pos_file_name = -1
        self.pos_file_hash = -1
        self.pos_mdate = -1
        self.pos_adate = -1
        self.pos_cdate = -1
        self.pos_ext = -1
        self.pos_path = -1
        self.init_positions()
        self.csv_database = None

    def can_handle(self, filename):
        if "lista de arquivos.csv" in filename.strip().lower():
            return True
        return False

    def configure_csv_database(self, csv_database):
        self.csv_database = csv_database
        self.csv_database.create_csv(["evidence", "name", "hash", "ext", "cdate", "mdate", "adate"])

    def get_expected_first_line(self):
        return ["Nome", "Atalho", "Tamanho", "Ext", "Marcador", "Categoria", "MD5", "SHA1", "Deletado", "Recuperado",
                "Acesso", "Modificação", "Criação", "Caminho", "TrackId"]

    def init_positions(self):
        col_pos = 0
        for header_item in self.get_expected_first_line():
            if header_item.lower() == 'nome':
                self.pos_file_name = col_pos
            if header_item.lower() == 'md5':
                self.pos_file_hash = col_pos
            if header_item.lower() == "modificação":
                self.pos_mdate = col_pos
            if header_item.lower() == "acesso":
                self.pos_adate = col_pos
            if header_item.lower() == "criação":
                self.pos_cdate = col_pos
            if header_item.lower() == "ext":
                self.pos_ext = col_pos
            if header_item.lower() == "caminho":
                self.pos_path = col_pos
            col_pos = col_pos + 1

    def process_row(self, row):
        name = row[self.pos_file_name]
        hash = row[self.pos_file_hash]
        ext = row[self.pos_ext]
        cdate = self.parse_datetime(row[self.pos_cdate])
        mdate = self.parse_datetime(row[self.pos_mdate])
        adate = self.parse_datetime(row[self.pos_adate])
        row_path = row[self.pos_path]
        first_index_delimiter = row_path.find("/", 0)
        second_index_delimiter = row_path.find("/", 1)
        if first_index_delimiter > -1 and second_index_delimiter > 0:
            evidence = row_path[first_index_delimiter:second_index_delimiter]
        else:
            evidence = "Missing"
        if len(hash) > 0:
            is_in_date_range = False
            if len(cdate) > 0:
                if self.is_event_in_selected_range(self.parsed_date(cdate)):
                    is_in_date_range = True
            if len(mdate) > 0:
                if self.is_event_in_selected_range(self.parsed_date(mdate)):
                    is_in_date_range = True
            if len(adate) > 0:
                if self.is_event_in_selected_range(self.parsed_date(adate)):
                    is_in_date_range = True
            if is_in_date_range:
                self.csv_database.csv_write_record([evidence, name, hash, ext, cdate, mdate, adate])
