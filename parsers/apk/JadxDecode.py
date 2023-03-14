from parsers import GenericParser
import subprocess
import os


class JadxDecode(GenericParser.GenericParser):
    def can_handle(self, filename):
        if ".apk" in filename.strip().lower():
            return True
        return False

    def run_subprocess(self, apk_file, apk_output):
        result = subprocess.run(['.\\bin\\jadx\\bin\\jadx.bat',
                                 '-d',
                                 apk_output,
                                 apk_file],
                                capture_output=True)
        for line in result.stdout.splitlines():
            print(str(line))
        for line in result.stderr.splitlines():
            print(str(line))
        print("jadx-end-"+apk_file)

    def process(self, filepath):
        basename = os.path.basename(filepath)
        outfile = self.output_dir+"jadx-decoded-"+basename
        self.run_subprocess(filepath, outfile)
