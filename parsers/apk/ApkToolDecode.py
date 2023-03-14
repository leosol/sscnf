from parsers import GenericParser
import subprocess
import os


class ApkToolDecode(GenericParser.GenericParser):
    def can_handle(self, filename):
        if ".apk" in filename.strip().lower():
            return True
        return False

    def run_subprocess(self, apk_file, apk_output):
        result = subprocess.run(['java',
                                 '-jar',
                                 '.\\bin\\apktool.jar',
                                 'decode',
                                 apk_file,
                                 '-f',
                                 '-o',
                                 apk_output],
                                capture_output=True)
        print(result.stdout)
        print(result.stderr)

    def process(self, filepath):
        basename = os.path.basename(filepath)
        outfile = self.output_dir+"apktool-decoded-"+basename
        self.run_subprocess(filepath, outfile)
