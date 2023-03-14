from parsers import GenericParser
import os
import shutil
import sqlite3


class iTunesBackupOldParser(GenericParser.GenericParser):

    def __init__(self):
        super().__init__()

    def can_handle(self, filename):
        return True

    def set_dest_dir(self, dest_dir):
        self.dest_dir = dest_dir

    def set_manifest_db(self, manifest_db):
        self.conn = sqlite3.connect(manifest_db)
        self.c = self.conn.cursor()

    def get_manifested_name(self, filename):
        sqlite_select_Query = """select relativePath from Files where FileId = ?"""
        self.c.execute(sqlite_select_Query, [filename])
        data = self.c.fetchall()
        if len(data) == 0:
            return None
        else:
            return data[0][0]

    def process(self, filepath):
        basename = os.path.basename(filepath)
        dst = self.get_manifested_name(basename)
        if dst is not None:
            dst_path = self.dest_dir + "" + str(dst).replace("/", "\\")
            only_dir_name = os.path.dirname(dst_path)
            os.makedirs(only_dir_name, exist_ok=True)
            shutil.copyfile(filepath, dst_path)


if __name__ == '__main__':
    parser = iTunesBackupOldParser()
    #parser.set_dest_dir("E:\\Temp\\out\\")
    #parser.set_manifest_db(
    #    "E:\\Temp\\iphone\\MobileSync\\Backup\\760d2ffa865ea437b2d274273219edceaa17a79b\\Manifest.db")
    #parser.process(
    #    "E:\\Temp\\iphone\\MobileSync\\Backup\\760d2ffa865ea437b2d274273219edceaa17a79b\\00\\0000b2e89a1c3cc18f66da434411f02ac9a7ca4b")
    parser.set_dest_dir("E:\\Temp\\simulated\\out\\")
    parser.set_manifest_db(
        "E:\\Temp\\simulated\\MobileSync\\Backup\\62b06edca5c18a46bdad46ef9b8f4fb8424338ba\\Manifest.db")
    parser.process(
        "E:\\Temp\\iphone\\MobileSync\\Backup\\760d2ffa865ea437b2d274273219edceaa17a79b\\00\\0000b2e89a1c3cc18f66da434411f02ac9a7ca4b")
